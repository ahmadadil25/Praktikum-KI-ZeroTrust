const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const bcrypt = require('bcryptjs');

const gatewayApp = require('../gateway/app');
const nilaiApp = require('../service-nilai/app');
const transkripApp = require('../service-transkrip/app');
const { getDb, closeDb } = require('../shared/db');
const { runSeed } = require('../database/seed');
const config = require('../shared/config');
const { ROLES, DEVICE_STATUS, GRADE_STATUS } = require('../shared/constants');

describe('Tahap 1: Fondasi, Database, & Health Check', () => {
  let db;

  before(() => {
    // Jalankan seeding database untuk memastikan state awal siap
    db = getDb();
    runSeed(db);
  });

  after(() => {
    closeDb();
  });

  describe('Health Check Endpoints', () => {
    it('API Gateway (PEP) harus mengembalikan status 200 pada GET /health', async () => {
      const res = await request(gatewayApp).get('/health');
      assert.equal(res.status, 200);
      assert.equal(res.body.status, 'ok');
      assert.equal(res.body.service, 'api-gateway');
      assert.equal(res.body.port, config.portGateway);
      assert.ok(res.body.timestamp);
    });

    it('Service Nilai harus mengembalikan status 200 pada GET /health', async () => {
      const res = await request(nilaiApp).get('/health');
      assert.equal(res.status, 200);
      assert.equal(res.body.status, 'ok');
      assert.equal(res.body.service, 'service-nilai');
      assert.equal(res.body.port, config.portNilai);
      assert.ok(res.body.timestamp);
    });

    it('Service Transkrip harus mengembalikan status 200 pada GET /health', async () => {
      const res = await request(transkripApp).get('/health');
      assert.equal(res.status, 200);
      assert.equal(res.body.status, 'ok');
      assert.equal(res.body.service, 'service-transkrip');
      assert.equal(res.body.port, config.portTranskrip);
      assert.ok(res.body.timestamp);
    });
  });

  describe('Database Schema & Seed Verification', () => {
    it('Tabel users harus memiliki tepat 6 user demo dengan password bcrypt valid', () => {
      const users = db.prepare('SELECT * FROM users ORDER BY id ASC').all();
      assert.equal(users.length, 6, 'Harus ada 6 pengguna');

      const admin = users.find((u) => u.username === 'admin1');
      assert.ok(admin, 'Admin1 harus ada');
      assert.equal(admin.role, ROLES.ADMIN);
      assert.equal(admin.nim, null);

      const dosen = users.filter((u) => u.role === ROLES.DOSEN);
      assert.equal(dosen.length, 2, 'Harus ada 2 dosen');

      const mhs = users.filter((u) => u.role === ROLES.MAHASISWA);
      assert.equal(mhs.length, 3, 'Harus ada 3 mahasiswa');
      mhs.forEach((m) => {
        assert.ok(m.nim, `Mahasiswa ${m.username} harus memiliki NIM`);
      });

      // Verifikasi password hash menggunakan bcrypt
      users.forEach((u) => {
        const match = bcrypt.compareSync('Password123!', u.password_hash);
        assert.equal(match, true, `Password untuk ${u.username} harus cocok dengan Password123!`);
      });
    });

    it('Setiap user harus memiliki tepat 1 device aktif terdaftar di tabel devices', () => {
      const devices = db.prepare(`
        SELECT d.*, u.username
        FROM devices d
        JOIN users u ON d.user_id = u.id
      `).all();

      assert.equal(devices.length, 6, 'Harus ada 6 device terdaftar');
      devices.forEach((d) => {
        assert.equal(d.status, DEVICE_STATUS.ACTIVE);
        assert.ok(d.device_id.startsWith('DEV-'), 'Format Device ID harus DEV-*');
      });
    });

    it('Tabel classes harus memiliki 2 kelas dengan dosen pengampu yang berbeda', () => {
      const classes = db.prepare(`
        SELECT c.*, u.nama as dosen_nama, u.role as dosen_role
        FROM classes c
        JOIN users u ON c.dosen_id = u.id
      `).all();

      assert.equal(classes.length, 2, 'Harus ada 2 kelas');
      const dosenIds = new Set(classes.map((c) => c.dosen_id));
      assert.equal(dosenIds.size, 2, 'Dosen pengampu kedua kelas harus berbeda');
      classes.forEach((c) => {
        assert.equal(c.dosen_role, ROLES.DOSEN);
      });
    });

    it('Tabel grades harus memiliki data nilai yang memadai untuk uji kepemilikan', () => {
      const grades = db.prepare(`
        SELECT g.*, u.username, c.kode_kelas
        FROM grades g
        JOIN users u ON g.mahasiswa_id = u.id
        JOIN classes c ON g.kelas_id = c.id
      `).all();

      assert.equal(grades.length, 4, 'Harus ada 4 entri nilai');
      
      const draftGrades = grades.filter((g) => g.status_final === GRADE_STATUS.DRAFT);
      const finalGrades = grades.filter((g) => g.status_final === GRADE_STATUS.FINAL);
      
      assert.ok(draftGrades.length > 0, 'Harus ada nilai dengan status draft (belum final)');
      assert.ok(finalGrades.length > 0, 'Harus ada nilai dengan status final');
    });

    it('Tabel transcripts harus memiliki data transkrip yang sesuai untuk nilai yang sudah final', () => {
      const transcripts = db.prepare(`
        SELECT t.*, u.nim
        FROM transcripts t
        JOIN users u ON t.mahasiswa_id = u.id
      `).all();

      assert.equal(transcripts.length, 1, 'Harus ada 1 transkrip awal');
      assert.equal(transcripts[0].nim, '220101');
      assert.equal(transcripts[0].kode_kelas, 'IF-302');
      assert.equal(transcripts[0].nilai_huruf, 'A');
    });

    it('Skrip seed harus idempotent (tidak membuat data duplikat saat dijalankan ulang)', () => {
      // Jalankan seeding sekali lagi
      runSeed(db);

      const userCount = db.prepare('SELECT count(*) as c FROM users').get().c;
      const deviceCount = db.prepare('SELECT count(*) as c FROM devices').get().c;
      const classCount = db.prepare('SELECT count(*) as c FROM classes').get().c;
      const gradeCount = db.prepare('SELECT count(*) as c FROM grades').get().c;
      const transcriptCount = db.prepare('SELECT count(*) as c FROM transcripts').get().c;

      assert.equal(userCount, 6, 'Jumlah user tetap 6');
      assert.equal(deviceCount, 6, 'Jumlah device tetap 6');
      assert.equal(classCount, 2, 'Jumlah kelas tetap 2');
      assert.equal(gradeCount, 4, 'Jumlah nilai tetap 4');
      assert.equal(transcriptCount, 1, 'Jumlah transkrip tetap 1');
    });
  });
});
