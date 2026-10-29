const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const { getDb } = require('../shared/db');
const { ROLES, DEVICE_STATUS, GRADE_STATUS } = require('../shared/constants');

function runSeed(dbInstance = null) {
  const db = dbInstance || getDb();

  // Pastikan skema dijalankan
  const schemaPath = path.resolve(__dirname, 'schema.sql');
  const schemaSql = fs.readFileSync(schemaPath, 'utf8');
  db.exec(schemaSql);

  const DEMO_PASSWORD = 'Password123!';
  const passwordHash = bcrypt.hashSync(DEMO_PASSWORD, 10);

  const seedTransaction = db.transaction(() => {
    // 1. Seed Users (1 Admin, 2 Dosen, 3 Mahasiswa)
    const usersData = [
      {
        username: 'admin1',
        nama: 'Administrator Sistem',
        role: ROLES.ADMIN,
        nim: null,
        deviceId: 'DEV-ADMIN-01',
      },
      {
        username: 'dosen_budi',
        nama: 'Dr. Budi Hartono, M.Kom.',
        role: ROLES.DOSEN,
        nim: null,
        deviceId: 'DEV-DOSEN-01',
      },
      {
        username: 'dosen_siti',
        nama: 'Siti Rahma, M.T.',
        role: ROLES.DOSEN,
        nim: null,
        deviceId: 'DEV-DOSEN-02',
      },
      {
        username: 'mhs_ahmad',
        nama: 'Ahmad Pratama',
        role: ROLES.MAHASISWA,
        nim: '220101',
        deviceId: 'DEV-MHS-01',
      },
      {
        username: 'mhs_bambang',
        nama: 'Bambang Wijaya',
        role: ROLES.MAHASISWA,
        nim: '220102',
        deviceId: 'DEV-MHS-02',
      },
      {
        username: 'mhs_citra',
        nama: 'Citra Dewi',
        role: ROLES.MAHASISWA,
        nim: '220103',
        deviceId: 'DEV-MHS-03',
      },
    ];

    const insertUser = db.prepare(`
      INSERT INTO users (username, password_hash, nama, role, nim)
      VALUES (@username, @password_hash, @nama, @role, @nim)
      ON CONFLICT(username) DO UPDATE SET
        password_hash = excluded.password_hash,
        nama = excluded.nama,
        role = excluded.role,
        nim = excluded.nim
    `);

    const insertDevice = db.prepare(`
      INSERT INTO devices (user_id, device_id, status)
      VALUES (@user_id, @device_id, @status)
      ON CONFLICT(user_id, device_id) DO UPDATE SET
        status = excluded.status
    `);

    const userMap = {};

    for (const u of usersData) {
      insertUser.run({
        username: u.username,
        password_hash: passwordHash,
        nama: u.nama,
        role: u.role,
        nim: u.nim,
      });

      const userRow = db.prepare('SELECT id, username FROM users WHERE username = ?').get(u.username);
      userMap[u.username] = userRow.id;

      insertDevice.run({
        user_id: userRow.id,
        device_id: u.deviceId,
        status: DEVICE_STATUS.ACTIVE,
      });
    }

    // 2. Seed Classes (2 Kelas dengan dosen pengampu berbeda)
    const classesData = [
      {
        kode_kelas: 'IF-301',
        nama_kelas: 'Kelas A - Keamanan Informasi',
        mata_kuliah: 'Keamanan Informasi',
        dosen_username: 'dosen_budi',
        sks: 3,
      },
      {
        kode_kelas: 'IF-302',
        nama_kelas: 'Kelas B - Sistem Terdistribusi',
        mata_kuliah: 'Sistem Terdistribusi',
        dosen_username: 'dosen_siti',
        sks: 3,
      },
    ];

    const insertClass = db.prepare(`
      INSERT INTO classes (kode_kelas, nama_kelas, mata_kuliah, dosen_id, sks)
      VALUES (@kode_kelas, @nama_kelas, @mata_kuliah, @dosen_id, @sks)
      ON CONFLICT(kode_kelas) DO UPDATE SET
        nama_kelas = excluded.nama_kelas,
        mata_kuliah = excluded.mata_kuliah,
        dosen_id = excluded.dosen_id,
        sks = excluded.sks
    `);

    const classMap = {};

    for (const c of classesData) {
      const dosenId = userMap[c.dosen_username];
      insertClass.run({
        kode_kelas: c.kode_kelas,
        nama_kelas: c.nama_kelas,
        mata_kuliah: c.mata_kuliah,
        dosen_id: dosenId,
        sks: c.sks,
      });

      const classRow = db.prepare('SELECT id, kode_kelas FROM classes WHERE kode_kelas = ?').get(c.kode_kelas);
      classMap[c.kode_kelas] = classRow.id;
    }

    // 3. Seed Grades (Data nilai cukup untuk menguji kepemilikan data & status final)
    const gradesData = [
      // Kelas IF-301 (Dosen Budi):
      // - mhs_ahmad: draft (belum final, nilai 88)
      // - mhs_bambang: draft (belum final, nilai 75)
      {
        mahasiswa_username: 'mhs_ahmad',
        kode_kelas: 'IF-301',
        nilai: 88.0,
        status_final: GRADE_STATUS.DRAFT,
      },
      {
        mahasiswa_username: 'mhs_bambang',
        kode_kelas: 'IF-301',
        nilai: 75.0,
        status_final: GRADE_STATUS.DRAFT,
      },
      // Kelas IF-302 (Dosen Siti):
      // - mhs_ahmad: sudah final (nilai 92) -> transkrip ada
      // - mhs_citra: draft (belum final, nilai 81)
      {
        mahasiswa_username: 'mhs_ahmad',
        kode_kelas: 'IF-302',
        nilai: 92.0,
        status_final: GRADE_STATUS.FINAL,
      },
      {
        mahasiswa_username: 'mhs_citra',
        kode_kelas: 'IF-302',
        nilai: 81.0,
        status_final: GRADE_STATUS.DRAFT,
      },
    ];

    const insertGrade = db.prepare(`
      INSERT INTO grades (mahasiswa_id, kelas_id, nilai, status_final, updated_at)
      VALUES (@mahasiswa_id, @kelas_id, @nilai, @status_final, datetime('now', 'localtime'))
      ON CONFLICT(mahasiswa_id, kelas_id) DO UPDATE SET
        nilai = excluded.nilai,
        status_final = excluded.status_final,
        updated_at = datetime('now', 'localtime')
    `);

    for (const g of gradesData) {
      insertGrade.run({
        mahasiswa_id: userMap[g.mahasiswa_username],
        kelas_id: classMap[g.kode_kelas],
        nilai: g.nilai,
        status_final: g.status_final,
      });
    }

    // 4. Seed Transcripts (Hanya untuk nilai yang sudah berstatus final)
    const insertTranscript = db.prepare(`
      INSERT INTO transcripts (mahasiswa_id, kelas_id, kode_kelas, mata_kuliah, sks, nilai_angka, nilai_huruf, finalized_at)
      VALUES (@mahasiswa_id, @kelas_id, @kode_kelas, @mata_kuliah, @sks, @nilai_angka, @nilai_huruf, datetime('now', 'localtime'))
      ON CONFLICT(mahasiswa_id, kelas_id) DO UPDATE SET
        nilai_angka = excluded.nilai_angka,
        nilai_huruf = excluded.nilai_huruf,
        finalized_at = datetime('now', 'localtime')
    `);

    // Ahmad sudah final di IF-302 (Sistem Terdistribusi, nilai 92 = A)
    insertTranscript.run({
      mahasiswa_id: userMap['mhs_ahmad'],
      kelas_id: classMap['IF-302'],
      kode_kelas: 'IF-302',
      mata_kuliah: 'Sistem Terdistribusi',
      sks: 3,
      nilai_angka: 92.0,
      nilai_huruf: 'A',
    });
  });

  seedTransaction();
  console.log('[SEED] Database berhasil di-seed (Idempotent).');
}

// Jalankan langsung jika script dieksekusi via CLI
if (require.main === module) {
  try {
    runSeed();
    process.exit(0);
  } catch (error) {
    console.error('[SEED] Gagal melakukan seeding database:', error);
    process.exit(1);
  }
}

module.exports = { runSeed };

