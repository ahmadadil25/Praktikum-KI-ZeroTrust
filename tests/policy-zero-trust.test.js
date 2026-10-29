const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const jwt = require('jsonwebtoken');

const gatewayApp = require('../gateway/app');
const nilaiApp = require('../service-nilai/app');
const transkripApp = require('../service-transkrip/app');
const { getDb, closeDb } = require('../shared/db');
const { runSeed } = require('../database/seed');
const config = require('../shared/config');
const { ROLES, HEADERS } = require('../shared/constants');

describe('Tahap 3 & 4: Zero Trust Policy Engine, PEP, & Service Security', () => {
  let db;
  let nilaiServer;
  let transkripServer;

  // Token & Device variables
  let tokenDosenBudi, deviceDosenBudi = 'DEV-DOSEN-01';
  let tokenDosenSiti, deviceDosenSiti = 'DEV-DOSEN-02';
  let tokenMhsAhmad, deviceMhsAhmad = 'DEV-MHS-01';
  let tokenMhsBambang, deviceMhsBambang = 'DEV-MHS-02';
  let tokenAdmin, deviceAdmin = 'DEV-ADMIN-01';
  let tokenService;

  before(async () => {
    db = getDb();
    runSeed(db);

    // Jalankan server internal Service Nilai dan Service Transkrip untuk pengujian proxy gateway
    await new Promise((resolve) => {
      nilaiServer = nilaiApp.listen(config.portNilai, () => {
        transkripServer = transkripApp.listen(config.portTranskrip, resolve);
      });
    });

    // 1. Login Dosen Budi (Pengampu IF-301)
    const resBudi = await request(gatewayApp)
      .post('/auth/login')
      .set('x-device-id', deviceDosenBudi)
      .send({ username: 'dosen_budi', password: 'Password123!' });
    tokenDosenBudi = resBudi.body.access_token;

    // 2. Login Dosen Siti (Pengampu IF-302)
    const resSiti = await request(gatewayApp)
      .post('/auth/login')
      .set('x-device-id', deviceDosenSiti)
      .send({ username: 'dosen_siti', password: 'Password123!' });
    tokenDosenSiti = resSiti.body.access_token;

    // 3. Login Mahasiswa Ahmad (NIM: 220101)
    const resAhmad = await request(gatewayApp)
      .post('/auth/login')
      .set('x-device-id', deviceMhsAhmad)
      .send({ username: 'mhs_ahmad', password: 'Password123!' });
    tokenMhsAhmad = resAhmad.body.access_token;

    // 4. Login Mahasiswa Bambang (NIM: 220102)
    const resBambang = await request(gatewayApp)
      .post('/auth/login')
      .set('x-device-id', deviceMhsBambang)
      .send({ username: 'mhs_bambang', password: 'Password123!' });
    tokenMhsBambang = resBambang.body.access_token;

    // 5. Login Admin
    const resAdmin = await request(gatewayApp)
      .post('/auth/login')
      .set('x-device-id', deviceAdmin)
      .send({ username: 'admin1', password: 'Password123!' });
    tokenAdmin = resAdmin.body.access_token;

    // 6. Dapatkan Service Token untuk Service Nilai
    const resService = await request(gatewayApp)
      .post('/auth/service')
      .send({
        client_id: config.serviceAuth.clientId,
        client_secret: config.serviceAuth.clientSecret,
      });
    tokenService = resService.body.access_token;
  });

  after(async () => {
    await new Promise((resolve) => {
      nilaiServer.close(() => {
        transkripServer.close(() => {
          closeDb();
          resolve();
        });
      });
    });
  });

  describe('1. Verifikasi Device & Token di Gateway PEP', () => {
    it('Request dengan device tidak terdaftar ditolak oleh PEP', async () => {
      const res = await request(gatewayApp)
        .get('/nilai')
        .set('Authorization', `Bearer ${tokenMhsAhmad}`)
        .set('x-device-id', 'DEV-PALSU-999');

      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'Forbidden Device');
      assert.ok(res.body.reason.includes('tidak terdaftar'));
    });

    it('Request tanpa header X-Device-ID ditolak oleh PEP', async () => {
      const res = await request(gatewayApp)
        .get('/nilai')
        .set('Authorization', `Bearer ${tokenMhsAhmad}`);

      assert.equal(res.status, 400);
      assert.equal(res.body.error, 'Bad Request');
      assert.ok(res.body.reason.includes('X-Device-ID'));
    });

    it('Request dengan token kedaluwarsa ditolak oleh PEP', async () => {
      // Buat token kedaluwarsa secara sengaja (-10 detik)
      const expiredToken = jwt.sign(
        { sub: 4, username: 'mhs_ahmad', role: ROLES.MAHASISWA, nim: '220101' },
        config.jwt.accessSecret,
        { expiresIn: -10 }
      );

      const res = await request(gatewayApp)
        .get('/nilai')
        .set('Authorization', `Bearer ${expiredToken}`)
        .set('x-device-id', deviceMhsAhmad);

      assert.equal(res.status, 401);
      assert.equal(res.body.error, 'Token Expired');
      assert.ok(res.body.reason.includes('kedaluwarsa'));
    });

    it('Request tanpa header Authorization ditolak oleh PEP', async () => {
      const res = await request(gatewayApp)
        .get('/nilai')
        .set('x-device-id', deviceMhsAhmad);

      assert.equal(res.status, 401);
      assert.equal(res.body.error, 'Unauthorized');
    });
  });

  describe('2. Kontrol Kepemilikan Data: Mahasiswa & Transkrip', () => {
    it('Mahasiswa Ahmad (NIM: 220101) diizinkan melihat transkrip miliknya sendiri', async () => {
      const res = await request(gatewayApp)
        .get('/transkrip/220101')
        .set('Authorization', `Bearer ${tokenMhsAhmad}`)
        .set('x-device-id', deviceMhsAhmad);

      assert.equal(res.status, 200);
      assert.equal(res.body.status, 'success');
      assert.equal(res.body.mahasiswa.nim, '220101');
    });

    it('Mahasiswa Ahmad (NIM: 220101) DITOLAK saat mencoba melihat transkrip Bambang (NIM: 220102)', async () => {
      const res = await request(gatewayApp)
        .get('/transkrip/220102')
        .set('Authorization', `Bearer ${tokenMhsAhmad}`)
        .set('x-device-id', deviceMhsAhmad);

      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'Access Denied');
      assert.ok(res.body.reason.includes('dilarang melihat transkrip milik mahasiswa lain'));
    });

    it('Admin diizinkan melihat transkrip mahasiswa mana pun', async () => {
      const res = await request(gatewayApp)
        .get('/transkrip/220101')
        .set('Authorization', `Bearer ${tokenAdmin}`)
        .set('x-device-id', deviceAdmin);

      assert.equal(res.status, 200);
      assert.equal(res.body.status, 'success');
      assert.equal(res.body.mahasiswa.nim, '220101');
    });
  });

  describe('3. Kontrol Kepemilikan Data: Dosen & Kelas Pengampu', () => {
    it('Dosen Budi (pengampu IF-301) DITOLAK saat mencoba mengubah nilai kelas IF-302 (diampu Dosen Siti)', async () => {
      // Nilai ID 4 adalah milik mhs_citra di kelas IF-302 (Dosen Siti)
      const res = await request(gatewayApp)
        .put('/nilai/4')
        .set('Authorization', `Bearer ${tokenDosenBudi}`)
        .set('x-device-id', deviceDosenBudi)
        .set('x-simulated-hour', '10') // Jam operasional (10.00)
        .send({ nilai: 95 });

      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'Access Denied');
      assert.ok(res.body.reason.includes('bukan pengampu'));

      // Verifikasi di database bahwa nilai TIDAK BERUBAH (tetap 81)
      const grade = db.prepare('SELECT nilai FROM grades WHERE id = 4').get();
      assert.equal(grade.nilai, 81.0, 'Nilai tidak boleh berubah saat request ditolak!');
    });

    it('Dosen Budi DITOLAK saat mencoba memfinalisasi kelas IF-302 (ID: 2) milik Dosen Siti', async () => {
      const res = await request(gatewayApp)
        .post('/kelas/2/finalisasi')
        .set('Authorization', `Bearer ${tokenDosenBudi}`)
        .set('x-device-id', deviceDosenBudi)
        .set('x-simulated-hour', '10');

      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'Access Denied');
      assert.ok(res.body.reason.includes('bukan pengampu'));
    });

    it('Mahasiswa DITOLAK saat mencoba mengubah nilai', async () => {
      const res = await request(gatewayApp)
        .put('/nilai/1')
        .set('Authorization', `Bearer ${tokenMhsAhmad}`)
        .set('x-device-id', deviceMhsAhmad)
        .set('x-simulated-hour', '10')
        .send({ nilai: 100 });

      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'Access Denied');
      assert.ok(res.body.reason.includes('Hanya dosen'));
    });
  });

  describe('4. Jam Akses Operasional (07.00 - 21.00 Asia/Jakarta)', () => {
    it('Perubahan nilai DITOLAK di luar jam akses operasional (simulasi jam 22.00 malam)', async () => {
      // Nilai ID 1 adalah milik mhs_ahmad di IF-301 (diampu Dosen Budi, nilai awal 88.0)
      const initialGrade = db.prepare('SELECT nilai FROM grades WHERE id = 1').get().nilai;

      const res = await request(gatewayApp)
        .put('/nilai/1')
        .set('Authorization', `Bearer ${tokenDosenBudi}`)
        .set('x-device-id', deviceDosenBudi)
        .set('x-simulated-hour', '22') // Di luar jam akses
        .send({ nilai: 99.0 });

      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'Access Denied');
      assert.ok(res.body.reason.includes('jam akses'));

      // Verifikasi di database: data TIDAK BERUBAH
      const currentGrade = db.prepare('SELECT nilai FROM grades WHERE id = 1').get().nilai;
      assert.equal(currentGrade, initialGrade, 'Nilai tidak boleh berubah jika ditolak karena jam akses!');
    });

    it('Perubahan nilai DITOLAK di luar jam akses operasional (simulasi jam 04.00 subuh)', async () => {
      const res = await request(gatewayApp)
        .put('/nilai/1')
        .set('Authorization', `Bearer ${tokenDosenBudi}`)
        .set('x-device-id', deviceDosenBudi)
        .set('x-simulated-hour', '4')
        .send({ nilai: 99.0 });

      assert.equal(res.status, 403);
      assert.ok(res.body.reason.includes('jam akses'));
    });

    it('Perubahan nilai DIIZINKAN dan BERHASIL dalam rentang jam operasional (simulasi jam 14.00 siang)', async () => {
      const res = await request(gatewayApp)
        .put('/nilai/1')
        .set('Authorization', `Bearer ${tokenDosenBudi}`)
        .set('x-device-id', deviceDosenBudi)
        .set('x-simulated-hour', '14') // Dalam jam akses
        .send({ nilai: 89.5 });

      assert.equal(res.status, 200);
      assert.equal(res.body.status, 'success');
      assert.equal(res.body.data.nilai, 89.5);

      // Verifikasi di database nilai terupdate
      const currentGrade = db.prepare('SELECT nilai FROM grades WHERE id = 1').get().nilai;
      assert.equal(currentGrade, 89.5);
    });
  });

  describe('5. Immutabilitas Nilai yang Sudah Berstatus FINAL', () => {
    it('Dosen Siti DITOLAK saat mencoba mengubah nilai yang sudah berstatus final (Grade ID: 3)', async () => {
      // Grade ID: 3 di IF-302 memiliki status_final = 1
      const res = await request(gatewayApp)
        .put('/nilai/3')
        .set('Authorization', `Bearer ${tokenDosenSiti}`)
        .set('x-device-id', deviceDosenSiti)
        .set('x-simulated-hour', '10')
        .send({ nilai: 99 });

      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'Access Denied');
      assert.ok(res.body.reason.includes('FINAL'));

      // Verifikasi di database nilai tetap 92
      const grade = db.prepare('SELECT nilai FROM grades WHERE id = 3').get();
      assert.equal(grade.nilai, 92.0);
    });
  });

  describe('6. Proteksi Akses Langsung ke Service (Tanpa Gateway / X-Gateway-Secret)', () => {
    it('Akses langsung ke Service Nilai tanpa X-Gateway-Secret DITOLAK (403)', async () => {
      const res = await request(nilaiApp)
        .get('/nilai')
        .set('Authorization', `Bearer ${tokenDosenBudi}`);

      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'Direct Access Forbidden');
    });

    it('Akses ke Service Nilai dengan X-Gateway-Secret BENAR tetapi TANPA TOKEN DITOLAK (401)', async () => {
      const res = await request(nilaiApp)
        .get('/nilai')
        .set('x-gateway-secret', config.gatewaySecret);

      assert.equal(res.status, 401);
      assert.equal(res.body.error, 'Unauthorized');
    });

    it('Akses langsung ke Service Transkrip tanpa X-Gateway-Secret DITOLAK (403)', async () => {
      const res = await request(transkripApp)
        .get('/transkrip/220101')
        .set('Authorization', `Bearer ${tokenAdmin}`);

      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'Direct Access Forbidden');
    });
  });

  describe('7. Proteksi Khusus POST /transkrip/sinkron (Hanya Token Service)', () => {
    it('Token Mahasiswa DITOLAK untuk sinkronisasi transkrip (403)', async () => {
      const res = await request(gatewayApp)
        .post('/transkrip/sinkron')
        .set('Authorization', `Bearer ${tokenMhsAhmad}`)
        .set('x-device-id', deviceMhsAhmad)
        .send({ kelas_id: 1 });

      assert.equal(res.status, 403);
      assert.ok(res.body.reason.includes('hanya dapat diakses menggunakan token service'));
    });

    it('Token Dosen DITOLAK untuk sinkronisasi transkrip (403)', async () => {
      const res = await request(gatewayApp)
        .post('/transkrip/sinkron')
        .set('Authorization', `Bearer ${tokenDosenBudi}`)
        .set('x-device-id', deviceDosenBudi)
        .send({ kelas_id: 1 });

      assert.equal(res.status, 403);
      assert.ok(res.body.reason.includes('hanya dapat diakses menggunakan token service'));
    });

    it('Token Admin DITOLAK untuk sinkronisasi transkrip (403)', async () => {
      const res = await request(gatewayApp)
        .post('/transkrip/sinkron')
        .set('Authorization', `Bearer ${tokenAdmin}`)
        .set('x-device-id', deviceAdmin)
        .send({ kelas_id: 1 });

      assert.equal(res.status, 403);
      assert.ok(res.body.reason.includes('hanya dapat diakses menggunakan token service'));
    });

    it('Token Service Nilai DIIZINKAN untuk sinkronisasi transkrip', async () => {
      const res = await request(gatewayApp)
        .post('/transkrip/sinkron')
        .set('Authorization', `Bearer ${tokenService}`)
        .send({
          kelas_id: 1,
          items: [
            {
              mahasiswa_id: 4,
              kelas_id: 1,
              kode_kelas: 'IF-301',
              mata_kuliah: 'Keamanan Informasi',
              sks: 3,
              nilai: 89.5,
            },
          ],
        });

      assert.equal(res.status, 200);
      assert.equal(res.body.status, 'success');
      assert.equal(res.body.synced_count, 1);

      // Verifikasi data masuk ke tabel transcripts
      const transcript = db.prepare(`
        SELECT * FROM transcripts WHERE mahasiswa_id = 4 AND kelas_id = 1
      `).get();
      assert.ok(transcript, 'Transkrip harus tersimpan di database');
      assert.equal(transcript.nilai_angka, 89.5);
      assert.equal(transcript.nilai_huruf, 'A');
    });
  });

  describe('8. Verifikasi Audit Log', () => {
    it('Audit log mencatat keputusan ALLOW dan DENY dengan detail lengkap', () => {
      const logs = db.prepare('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 50').all();
      assert.ok(logs.length > 0, 'Audit logs tidak boleh kosong');

      const allowLogs = logs.filter((l) => l.hasil === 'ALLOW');
      const denyLogs = logs.filter((l) => l.hasil === 'DENY');

      assert.ok(allowLogs.length > 0, 'Harus ada pencatatan ALLOW');
      assert.ok(denyLogs.length > 0, 'Harus ada pencatatan DENY');

      logs.forEach((log) => {
        assert.ok(log.waktu, 'Log harus memiliki waktu');
        assert.ok(log.subject, 'Log harus memiliki subject');
        assert.ok(log.endpoint, 'Log harus memiliki endpoint');
        assert.ok(log.device_id !== undefined, 'Log harus memiliki device_id');
        assert.ok(['ALLOW', 'DENY'].includes(log.hasil), 'Hasil harus ALLOW atau DENY');
        assert.ok(log.alasan, 'Log harus memiliki alasan');
      });
    });
  });
});
