const express = require('express');
const config = require('../shared/config');
const { getDb } = require('../shared/db');
const { verifyResourceSecurity } = require('../shared/verify-resource-security');
const { ROLES } = require('../shared/constants');

const app = express();

app.use(express.json());

// Endpoint Health Check (Publik untuk pemantauan layanan)
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'service-nilai',
    role: 'Resource Service (Nilai & Kelas)',
    port: config.portNilai,
    timestamp: new Date().toISOString(),
  });
});

// Lindungi seluruh endpoint bisnis dengan verifikasi gateway secret & token
app.use(verifyResourceSecurity);

/**
 * GET /nilai
 * Mahasiswa melihat nilainya sendiri; Dosen melihat nilai mahasiswa di kelas yang diampunya
 */
app.get('/nilai', (req, res) => {
  const db = getDb();
  const user = req.user;

  if (user.role === ROLES.MAHASISWA) {
    const grades = db.prepare(`
      SELECT g.id, g.nilai, g.status_final, g.updated_at,
             c.kode_kelas, c.nama_kelas, c.mata_kuliah, c.sks,
             d.nama as dosen_pengampu
      FROM grades g
      JOIN classes c ON g.kelas_id = c.id
      JOIN users d ON c.dosen_id = d.id
      WHERE g.mahasiswa_id = ?
      ORDER BY c.kode_kelas ASC
    `).all(user.sub);

    return res.status(200).json({
      status: 'success',
      role: user.role,
      user_id: user.sub,
      data: grades,
    });
  }

  if (user.role === ROLES.DOSEN) {
    const grades = db.prepare(`
      SELECT g.id, g.nilai, g.status_final, g.updated_at,
             c.kode_kelas, c.nama_kelas, c.mata_kuliah, c.sks,
             m.nim as mahasiswa_nim, m.nama as mahasiswa_nama
      FROM grades g
      JOIN classes c ON g.kelas_id = c.id
      JOIN users m ON g.mahasiswa_id = m.id
      WHERE c.dosen_id = ?
      ORDER BY c.kode_kelas ASC, m.nim ASC
    `).all(user.sub);

    return res.status(200).json({
      status: 'success',
      role: user.role,
      dosen_id: user.sub,
      data: grades,
    });
  }

  return res.status(403).json({
    error: 'Forbidden',
    reason: 'Role tidak memiliki izin mengakses data nilai',
  });
});

/**
 * PUT /nilai/:id
 * Dosen mengubah nilai pada kelas yang diampu (belum final)
 */
app.put('/nilai/:id', (req, res) => {
  const db = getDb();
  const gradeId = parseInt(req.params.id, 10);
  const { nilai } = req.body || {};

  if (nilai === undefined || nilai === null || isNaN(nilai) || nilai < 0 || nilai > 100) {
    return res.status(400).json({
      error: 'Bad Request',
      reason: 'Nilai harus berupa angka antara 0 dan 100',
    });
  }

  const existingGrade = db.prepare('SELECT * FROM grades WHERE id = ?').get(gradeId);
  if (!existingGrade) {
    return res.status(404).json({
      error: 'Not Found',
      reason: `Nilai ID ${gradeId} tidak ditemukan`,
    });
  }

  if (existingGrade.status_final === 1) {
    return res.status(400).json({
      error: 'Already Finalized',
      reason: 'Nilai sudah berstatus final dan tidak dapat diubah lagi',
    });
  }

  db.prepare(`
    UPDATE grades
    SET nilai = ?, updated_at = datetime('now', 'localtime')
    WHERE id = ?
  `).run(Number(nilai), gradeId);

  const updated = db.prepare(`
    SELECT g.*, c.kode_kelas, c.mata_kuliah, m.nim, m.nama as mahasiswa_nama
    FROM grades g
    JOIN classes c ON g.kelas_id = c.id
    JOIN users m ON g.mahasiswa_id = m.id
    WHERE g.id = ?
  `).get(gradeId);

  return res.status(200).json({
    status: 'success',
    message: `Nilai untuk mahasiswa ${updated.mahasiswa_nama} (${updated.kode_kelas}) berhasil diperbarui`,
    data: updated,
  });
});

/**
 * POST /kelas/:id/finalisasi
 * Dosen memfinalisasi seluruh nilai pada kelas, lalu memanggil sinkronisasi transkrip via Gateway
 */
app.post('/kelas/:id/finalisasi', async (req, res) => {
  const db = getDb();
  const classId = parseInt(req.params.id, 10);

  const classRow = db.prepare('SELECT * FROM classes WHERE id = ?').get(classId);
  if (!classRow) {
    return res.status(404).json({
      error: 'Not Found',
      reason: `Kelas ID ${classId} tidak ditemukan`,
    });
  }

  // Finalisasi seluruh nilai di kelas ini dalam transaksi
  const finalizeTx = db.transaction(() => {
    db.prepare(`
      UPDATE grades
      SET status_final = 1, updated_at = datetime('now', 'localtime')
      WHERE kelas_id = ?
    `).run(classId);

    return db.prepare(`
      SELECT g.mahasiswa_id, g.kelas_id, g.nilai,
             c.kode_kelas, c.mata_kuliah, c.sks,
             m.nim, m.nama as mahasiswa_nama
      FROM grades g
      JOIN classes c ON g.kelas_id = c.id
      JOIN users m ON g.mahasiswa_id = m.id
      WHERE g.kelas_id = ?
    `).all(classId);
  });

  const finalizedGrades = finalizeTx();

  // Pemanggilan Antar-Service sesuai Arsitektur Zero Trust:
  // 1. Dapatkan Token Service dari Gateway (POST /auth/service)
  // 2. Kirim data nilai final ke Service Transkrip melalui Gateway (POST /transkrip/sinkron)
  let syncResult = null;
  try {
    const tokenRes = await fetch(`${config.gatewayUrl}/auth/service`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: config.serviceAuth.clientId,
        client_secret: config.serviceAuth.clientSecret,
      }),
    });

    if (!tokenRes.ok) {
      const errBody = await tokenRes.json().catch(() => ({}));
      throw new Error(`Gagal memperoleh service token: ${errBody.reason || tokenRes.statusText}`);
    }

    const { access_token: serviceToken } = await tokenRes.json();

    // Kirim sinkronisasi ke Gateway (Gateway PEP akan memverifikasi token service & meneruskan ke Service Transkrip)
    const syncRes = await fetch(`${config.gatewayUrl}/transkrip/sinkron`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${serviceToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        kelas_id: classId,
        items: finalizedGrades,
      }),
    });

    syncResult = await syncRes.json();
  } catch (syncError) {
    console.error('[SERVICE NILAI ERROR] Gagal melakukan sinkronisasi transkrip via Gateway:', syncError.message);
    syncResult = {
      status: 'partial_success',
      warning: `Nilai berhasil difinalisasi secara lokal, namun sinkronisasi otomatis ke Gateway gagal: ${syncError.message}`,
    };
  }

  return res.status(200).json({
    status: 'success',
    message: `Kelas ${classRow.nama_kelas} (${classRow.kode_kelas}) berhasil difinalisasi`,
    finalized_count: finalizedGrades.length,
    sync_result: syncResult,
  });
});

module.exports = app;
