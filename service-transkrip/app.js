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
    service: 'service-transkrip',
    role: 'Resource Service (Transkrip Akademik)',
    port: config.portTranskrip,
    timestamp: new Date().toISOString(),
  });
});

// Lindungi seluruh endpoint bisnis dengan verifikasi gateway secret & token
app.use(verifyResourceSecurity);

/**
 * Konversi nilai angka ke nilai huruf standar akademik
 */
function toLetterGrade(score) {
  if (score >= 85) return 'A';
  if (score >= 75) return 'B';
  if (score >= 65) return 'C';
  if (score >= 50) return 'D';
  return 'E';
}

/**
 * GET /transkrip/:nim
 * Mahasiswa hanya melihat transkrip miliknya; Admin dapat melihat transkrip seluruh mahasiswa
 */
app.get('/transkrip/:nim', (req, res) => {
  const db = getDb();
  const targetNim = req.params.nim;
  const user = req.user;

  // Verifikasi otorisasi di tingkat service (Defense in Depth)
  if (user.role === ROLES.MAHASISWA && String(user.nim) !== String(targetNim)) {
    return res.status(403).json({
      error: 'Forbidden',
      reason: 'Mahasiswa hanya diizinkan melihat transkrip miliknya sendiri',
    });
  }

  if (user.role !== ROLES.MAHASISWA && user.role !== ROLES.ADMIN) {
    return res.status(403).json({
      error: 'Forbidden',
      reason: 'Role tidak diizinkan mengakses data transkrip',
    });
  }

  const student = db.prepare('SELECT id, username, nama, nim FROM users WHERE nim = ?').get(targetNim);
  if (!student) {
    return res.status(404).json({
      error: 'Not Found',
      reason: `Mahasiswa dengan NIM ${targetNim} tidak ditemukan`,
    });
  }

  const transcripts = db.prepare(`
    SELECT t.id, t.kode_kelas, t.mata_kuliah, t.sks, t.nilai_angka, t.nilai_huruf, t.finalized_at
    FROM transcripts t
    WHERE t.mahasiswa_id = ?
    ORDER BY t.kode_kelas ASC
  `).all(student.id);

  const totalSks = transcripts.reduce((sum, item) => sum + (item.sks || 0), 0);

  return res.status(200).json({
    status: 'success',
    mahasiswa: {
      nim: student.nim,
      nama: student.nama,
    },
    total_mata_kuliah: transcripts.length,
    total_sks: totalSks,
    transkrip: transcripts,
  });
});

/**
 * POST /transkrip/sinkron
 * HANYA menerima Token Service dari Service Nilai (Role: SERVICE)
 * Token pengguna (termasuk Admin, Dosen, Mahasiswa) WAJIB DITOLAK!
 */
app.post('/transkrip/sinkron', (req, res) => {
  const user = req.user;

  // Verifikasi ketat role: service
  if (!user || user.role !== ROLES.SERVICE) {
    return res.status(403).json({
      error: 'Forbidden Service Endpoint',
      reason: 'Endpoint sinkronisasi transkrip HANYA dapat diakses menggunakan Token Service sah dari Service Nilai.',
    });
  }

  const db = getDb();
  const { kelas_id, items } = req.body || {};

  if (!kelas_id && (!items || items.length === 0)) {
    return res.status(400).json({
      error: 'Bad Request',
      reason: 'Parameter kelas_id atau daftar items nilai wajib disertakan',
    });
  }

  let gradesToSync = items;

  // Jika items tidak disertakan secara manual, ambil nilai final langsung dari database
  if (!gradesToSync || gradesToSync.length === 0) {
    gradesToSync = db.prepare(`
      SELECT g.mahasiswa_id, g.kelas_id, g.nilai,
             c.kode_kelas, c.mata_kuliah, c.sks
      FROM grades g
      JOIN classes c ON g.kelas_id = c.id
      WHERE g.kelas_id = ? AND g.status_final = 1
    `).all(kelas_id);
  }

  const syncTx = db.transaction(() => {
    const insertOrUpdate = db.prepare(`
      INSERT INTO transcripts (mahasiswa_id, kelas_id, kode_kelas, mata_kuliah, sks, nilai_angka, nilai_huruf, finalized_at)
      VALUES (@mahasiswa_id, @kelas_id, @kode_kelas, @mata_kuliah, @sks, @nilai_angka, @nilai_huruf, datetime('now', 'localtime'))
      ON CONFLICT(mahasiswa_id, kelas_id) DO UPDATE SET
        nilai_angka = excluded.nilai_angka,
        nilai_huruf = excluded.nilai_huruf,
        kode_kelas = excluded.kode_kelas,
        mata_kuliah = excluded.mata_kuliah,
        sks = excluded.sks,
        finalized_at = datetime('now', 'localtime')
    `);

    for (const item of gradesToSync) {
      const letterGrade = toLetterGrade(Number(item.nilai));
      insertOrUpdate.run({
        mahasiswa_id: item.mahasiswa_id,
        kelas_id: item.kelas_id || kelas_id,
        kode_kelas: item.kode_kelas,
        mata_kuliah: item.mata_kuliah,
        sks: item.sks || 3,
        nilai_angka: Number(item.nilai),
        nilai_huruf: letterGrade,
      });
    }
  });

  syncTx();

  return res.status(200).json({
    status: 'success',
    message: `Berhasil menyinkronkan ${gradesToSync.length} nilai ke transkrip mahasiswa`,
    synced_count: gradesToSync.length,
  });
});

module.exports = app;
