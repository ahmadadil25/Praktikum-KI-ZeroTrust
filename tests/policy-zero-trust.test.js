const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const jwt = require('jsonwebtoken');

const gatewayApp = require('../gateway/app');
const nilaiApp = require('../service-nilai/app');
const transkripApp = require('../service-transkrip/app');
const { getDb, closeDb } = require('../shared/db');
const { runSeed } = require('../database/seed');
const { resetDatabase } = require('../database/reset');
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
    resetDatabase();
    db = getDb();

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
    it('Request dengan device tidak terdaftar ditolak oleh PEP (403)', async () => {
      const res = await request(gatewayApp)
        .get('/nilai')
        .set('Authorization', `Bearer ${tokenMhsAhmad}`)
        .set('x-device-id', 'DEV-PALSU-999');

      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'Forbidden Device');
      assert.ok(res.body.reason.includes('tidak terdaftar'));
    });

    it('Request tanpa header X-Device-ID ditolak oleh PEP (400)', async () => {
      const res = await request(gatewayApp)
        .get('/nilai')
        .set('Authorization', `Bearer ${tokenMhsAhmad}`);

      assert.equal(res.status, 400);
      assert.equal(res.body.error, 'Bad Request');
      assert.ok(res.body.reason.includes('X-Device-ID'));
    });

    it('Request dengan token kedaluwarsa ditolak oleh PEP (401)', async () => {
      const expiredToken = jwt.sign(
        { sub: 4, username: 'mhs_ahmad', role: ROLES.MAHASISWA, nim: '220101' },
        config.jwt.accessSecret,
        { expiresIn: -10, issuer: 'zero-trust-gateway' }
      );

      const res = await request(gatewayApp)
        .get('/nilai')
        .set('Authorization', `Bearer ${expiredToken}`)
        .set('x-device-id', deviceMhsAhmad);

      assert.equal(res.status, 401);
      assert.equal(res.body.error, 'Token Expired');
      assert.ok(res.body.reason.includes('kedaluwarsa'));
    });

    it('Request tanpa header Authorization ditolak oleh PEP (401)', async () => {
      const res = await request(gatewayApp)
        .get('/nilai')
        .set('x-device-id', deviceMhsAhmad);

      assert.equal(res.status, 401);
      assert.equal(res.body.error, 'Unauthorized');
    });
  });

  describe('2. Kontrol Kepemilikan Data: Mahasiswa (Nilai & Transkrip)', () => {
    it('G.1: Mahasiswa hanya melihat nilai miliknya pada GET /nilai', async () => {
      const res = await request(gatewayApp)
        .get('/nilai')
        .set('Authorization', `Bearer ${tokenMhsAhmad}`)
        .set('x-device-id', deviceMhsAhmad);

      assert.equal(res.status, 200);
      assert.equal(res.body.status, 'success');
      assert.equal(res.body.user_id, 4); // Ahmad ID
      // Ahmad hanya terdaftar di IF-301 dan IF-302
      assert.equal(res.body.data.length, 2);
    });

    it('G.2: Mahasiswa diizinkan melihat detail nilai miliknya sendiri pada GET /nilai/:id', async () => {
      // Nilai ID 1 adalah milik mhs_ahmad (IF-301)
      const res = await request(gatewayApp)
        .get('/nilai/1')
        .set('Authorization', `Bearer ${tokenMhsAhmad}`)
        .set('x-device-id', deviceMhsAhmad);

      assert.equal(res.status, 200);
      assert.equal(res.body.status, 'success');
      assert.equal(res.body.data.mahasiswa_id, 4);
    });

    it('G.2: Mahasiswa DITOLAK ketika mengakses nilai mahasiswa lain pada GET /nilai/:id (403)', async () => {
      // Nilai ID 2 adalah milik mhs_bambang (IF-301)
      const res = await request(gatewayApp)
        .get('/nilai/2')
        .set('Authorization', `Bearer ${tokenMhsAhmad}`)
        .set('x-device-id', deviceMhsAhmad);

      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'Access Denied');
      assert.ok(res.body.reason.includes('dilarang mengakses nilai milik mahasiswa lain'));
    });

    it('Mahasiswa Ahmad (NIM: 220101) diizinkan melihat transkrip miliknya sendiri', async () => {
      const res = await request(gatewayApp)
        .get('/transkrip/220101')
        .set('Authorization', `Bearer ${tokenMhsAhmad}`)
        .set('x-device-id', deviceMhsAhmad);

      assert.equal(res.status, 200);
      assert.equal(res.body.status, 'success');
      assert.equal(res.body.mahasiswa.nim, '220101');
    });

    it('G.2: Mahasiswa Ahmad DITOLAK saat mencoba melihat transkrip Bambang (NIM: 220102) (403)', async () => {
      const res = await request(gatewayApp)
        .get('/transkrip/220102')
        .set('Authorization', `Bearer ${tokenMhsAhmad}`)
        .set('x-device-id', deviceMhsAhmad);

      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'Access Denied');
      assert.ok(res.body.reason.includes('dilarang melihat transkrip milik mahasiswa lain'));
    });

    it('G.11: Admin diizinkan melihat transkrip mahasiswa mana pun', async () => {
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
    it('G.3: Dosen hanya dapat melihat nilai pada kelas yang diampunya (GET /nilai)', async () => {
      const res = await request(gatewayApp)
        .get('/nilai')
        .set('Authorization', `Bearer ${tokenDosenBudi}`)
        .set('x-device-id', deviceDosenBudi);

      assert.equal(res.status, 200);
      assert.equal(res.body.dosen_id, 2); // Budi ID
      // Budi hanya mengampu IF-301 (2 mahasiswa: Ahmad dan Bambang)
      assert.equal(res.body.data.length, 2);
      res.body.data.forEach((g) => {
        assert.equal(g.kode_kelas, 'IF-301');
      });
    });

    it('G.3: Dosen Budi (pengampu IF-301) DITOLAK saat mencoba mengubah nilai kelas IF-302 (diampu Dosen Siti)', async () => {
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

    it('Mahasiswa DITOLAK saat mencoba mengubah nilai (403)', async () => {
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
    it('G.5: Perubahan nilai DITOLAK di luar jam akses operasional (simulasi jam 22.00 malam)', async () => {
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

    it('G.5: Finalisasi kelas DITOLAK di luar jam akses operasional (simulasi jam 23.00 malam)', async () => {
      const res = await request(gatewayApp)
        .post('/kelas/1/finalisasi')
        .set('Authorization', `Bearer ${tokenDosenBudi}`)
        .set('x-device-id', deviceDosenBudi)
        .set('x-simulated-hour', '23');

      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'Access Denied');
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
    it('G.4: Dosen Siti DITOLAK saat mencoba mengubah nilai yang sudah berstatus final (Grade ID: 3)', async () => {
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
    it('G.9: Akses langsung ke Service Nilai tanpa X-Gateway-Secret DITOLAK (403)', async () => {
      const res = await request(nilaiApp)
        .get('/nilai')
        .set('Authorization', `Bearer ${tokenDosenBudi}`);

      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'Direct Access Forbidden');
    });

    it('G.10: Akses ke Service Nilai dengan X-Gateway-Secret BENAR tetapi TANPA TOKEN DITOLAK (401)', async () => {
      const res = await request(nilaiApp)
        .get('/nilai')
        .set('x-gateway-secret', config.gatewaySecret);

      assert.equal(res.status, 401);
      assert.equal(res.body.error, 'Unauthorized');
    });

    it('G.9: Akses langsung ke Service Transkrip tanpa X-Gateway-Secret DITOLAK (403)', async () => {
      const res = await request(transkripApp)
        .get('/transkrip/220101')
        .set('Authorization', `Bearer ${tokenAdmin}`);

      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'Direct Access Forbidden');
    });
  });

  describe('7. Proteksi Khusus POST /transkrip/sinkron & Validasi Token Service', () => {
    it('G.7: Token Mahasiswa DITOLAK untuk sinkronisasi transkrip (403)', async () => {
      const res = await request(gatewayApp)
        .post('/transkrip/sinkron')
        .set('Authorization', `Bearer ${tokenMhsAhmad}`)
        .set('x-device-id', deviceMhsAhmad)
        .send({ kelas_id: 1 });

      assert.equal(res.status, 403);
      assert.ok(res.body.reason.includes('hanya dapat diakses menggunakan token service'));
    });

    it('G.7: Token Dosen DITOLAK untuk sinkronisasi transkrip (403)', async () => {
      const res = await request(gatewayApp)
        .post('/transkrip/sinkron')
        .set('Authorization', `Bearer ${tokenDosenBudi}`)
        .set('x-device-id', deviceDosenBudi)
        .send({ kelas_id: 1 });

      assert.equal(res.status, 403);
      assert.ok(res.body.reason.includes('hanya dapat diakses menggunakan token service'));
    });

    it('G.7 & G.11: Token Admin DITOLAK untuk sinkronisasi transkrip (403)', async () => {
      const res = await request(gatewayApp)
        .post('/transkrip/sinkron')
        .set('Authorization', `Bearer ${tokenAdmin}`)
        .set('x-device-id', deviceAdmin)
        .send({ kelas_id: 1 });

      assert.equal(res.status, 403);
      assert.ok(res.body.reason.includes('hanya dapat diakses menggunakan token service'));
    });

    it('G.8: Sinkronisasi DITOLAK jika token service kedaluwarsa (401)', async () => {
      const expiredServiceToken = jwt.sign(
        { sub: 'service-nilai', role: ROLES.SERVICE, service: 'service-nilai' },
        config.jwt.serviceSecret,
        { expiresIn: -10, issuer: 'zero-trust-gateway' }
      );

      const res = await request(gatewayApp)
        .post('/transkrip/sinkron')
        .set('Authorization', `Bearer ${expiredServiceToken}`)
        .send({ kelas_id: 1 });

      assert.equal(res.status, 401);
      assert.equal(res.body.error, 'Token Expired');
    });

    it('G.8: Sinkronisasi DITOLAK jika token service tidak valid / palsu (401)', async () => {
      const forgedToken = jwt.sign(
        { sub: 'service-nilai', role: ROLES.SERVICE },
        'wrong-secret-key-signature',
        { expiresIn: '5m', issuer: 'zero-trust-gateway' }
      );

      const res = await request(gatewayApp)
        .post('/transkrip/sinkron')
        .set('Authorization', `Bearer ${forgedToken}`)
        .send({ kelas_id: 1 });

      assert.equal(res.status, 401);
      assert.equal(res.body.error, 'Invalid Token');
    });

    it('Token Service Nilai sah DIIZINKAN untuk sinkronisasi transkrip (200)', async () => {
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
    });

    it('G.13: Pengulangan sinkronisasi (Idempotency) tidak membuat duplikasi data di tabel transkrip', async () => {
      // Hitung jumlah awal
      const countBefore = db.prepare('SELECT count(*) as c FROM transcripts').get().c;

      // Kirim sinkronisasi ulang dengan data yang sama
      const resRetry = await request(gatewayApp)
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

      assert.equal(resRetry.status, 200);

      const countAfter = db.prepare('SELECT count(*) as c FROM transcripts').get().c;
      assert.equal(countAfter, countBefore, 'Jumlah transkrip tidak boleh bertambah saat sinkronisasi diulang!');
    });
  });

  describe('8. Penanganan Kegagalan Sinkronisasi (Fault Handling)', () => {
    it('G.14: Kegagalan sinkronisasi transkrip ditangani dan tidak memberi respon sukses palsu (502)', async () => {
      // Tutup sementara Service Transkrip untuk mensimulasikan kegagalan sinkronisasi
      await new Promise((resolve) => transkripServer.close(resolve));

      // Dosen mencoba memfinalisasi kelas saat downstream transkrip tidak dapat dihubungi
      const res = await request(gatewayApp)
        .post('/kelas/1/finalisasi')
        .set('Authorization', `Bearer ${tokenDosenBudi}`)
        .set('x-device-id', deviceDosenBudi)
        .set('x-simulated-hour', '10');

      assert.equal(res.status, 502);
      assert.equal(res.body.status, 'error');
      assert.equal(res.body.error, 'Synchronization Failed');
      assert.ok(res.body.message.includes('sinkronisasi transkrip melalui gateway gagal'));

      // Nyalakan kembali server transkrip untuk pengujian berikutnya
      await new Promise((resolve) => {
        transkripServer = transkripApp.listen(config.portTranskrip, resolve);
      });
    });
  });

  describe('9. Verifikasi Audit Log & Proteksi Secret Log', () => {
    it('G.12: Audit log mencatat keputusan ALLOW dan DENY dengan detail lengkap', () => {
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

        // Pastikan tidak ada token mentah atau password yang bocor di log
        assert.equal(log.alasan.includes('Bearer eyJ'), false, 'Tidak boleh ada raw JWT di alasan log');
        assert.equal(log.subject.includes('eyJ'), false, 'Tidak boleh ada raw JWT di subject log');
      });
    });
  });
});
