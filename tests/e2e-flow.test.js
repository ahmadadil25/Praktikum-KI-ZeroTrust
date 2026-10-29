const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');

const gatewayApp = require('../gateway/app');
const nilaiApp = require('../service-nilai/app');
const transkripApp = require('../service-transkrip/app');
const { getDb, closeDb } = require('../shared/db');
const { runSeed } = require('../database/seed');
const config = require('../shared/config');

describe('End-to-End Zero Trust Workflow: Login -> Edit Nilai -> Finalisasi -> Sinkronisasi -> Transkrip', () => {
  let db;
  let gatewayServer, nilaiServer, transkripServer;

  before(async () => {
    db = getDb();
    runSeed(db);

    // Jalankan ketiga server pada port aslinya untuk pengujian inter-service call HTTP
    await new Promise((resolve) => {
      gatewayServer = gatewayApp.listen(config.portGateway, () => {
        nilaiServer = nilaiApp.listen(config.portNilai, () => {
          transkripServer = transkripApp.listen(config.portTranskrip, resolve);
        });
      });
    });
  });

  after(async () => {
    await new Promise((resolve) => {
      gatewayServer.close(() => {
        nilaiServer.close(() => {
          transkripServer.close(() => {
            closeDb();
            resolve();
          });
        });
      });
    });
  });

  it('Alur lengkap: Dosen edit nilai -> finalisasi kelas -> sinkronisasi via token service -> Mahasiswa cek transkrip', async () => {
    // 1. Dosen Budi Login melalui Gateway PEP
    const loginDosen = await request(gatewayApp)
      .post('/auth/login')
      .set('x-device-id', 'DEV-DOSEN-01')
      .send({ username: 'dosen_budi', password: 'Password123!' });

    assert.equal(loginDosen.status, 200);
    const tokenDosen = loginDosen.body.access_token;
    assert.ok(tokenDosen);

    // 2. Dosen Budi melihat daftar nilai kelasnya (GET /nilai)
    const listNilai = await request(gatewayApp)
      .get('/nilai')
      .set('Authorization', `Bearer ${tokenDosen}`)
      .set('x-device-id', 'DEV-DOSEN-01');

    assert.equal(listNilai.status, 200);
    assert.ok(listNilai.body.data.length >= 2);

    // 3. Dosen Budi mengubah nilai Ahmad di kelas IF-301 (ID: 1) menjadi 95.0
    const updateNilai = await request(gatewayApp)
      .put('/nilai/1')
      .set('Authorization', `Bearer ${tokenDosen}`)
      .set('x-device-id', 'DEV-DOSEN-01')
      .set('x-simulated-hour', '10') // Jam operasional (10.00 WIB)
      .send({ nilai: 95.0 });

    assert.equal(updateNilai.status, 200);
    assert.equal(updateNilai.body.data.nilai, 95.0);

    // 4. Dosen Budi memfinalisasi kelas IF-301 (ID: 1)
    // Service Nilai akan otomatis meminta token service ke Gateway lalu menyinkronkan nilai ke Service Transkrip
    const finalisasi = await request(gatewayApp)
      .post('/kelas/1/finalisasi')
      .set('Authorization', `Bearer ${tokenDosen}`)
      .set('x-device-id', 'DEV-DOSEN-01')
      .set('x-simulated-hour', '10');

    assert.equal(finalisasi.status, 200);
    assert.equal(finalisasi.body.status, 'success');
    assert.ok(finalisasi.body.sync_result);
    assert.equal(finalisasi.body.sync_result.status, 'success');

    // 5. Mahasiswa Ahmad login dengan device-nya
    const loginAhmad = await request(gatewayApp)
      .post('/auth/login')
      .set('x-device-id', 'DEV-MHS-01')
      .send({ username: 'mhs_ahmad', password: 'Password123!' });

    assert.equal(loginAhmad.status, 200);
    const tokenAhmad = loginAhmad.body.access_token;

    // 6. Mahasiswa Ahmad memeriksa transkripnya (GET /transkrip/220101)
    // Harus melihat nilai IF-301 yang baru disinkronkan dengan nilai angka 95.0 dan nilai huruf A
    const transkripAhmad = await request(gatewayApp)
      .get('/transkrip/220101')
      .set('Authorization', `Bearer ${tokenAhmad}`)
      .set('x-device-id', 'DEV-MHS-01');

    assert.equal(transkripAhmad.status, 200);
    const courses = transkripAhmad.body.transkrip;
    const if301 = courses.find((c) => c.kode_kelas === 'IF-301');

    assert.ok(if301, 'Mata kuliah IF-301 harus masuk ke transkrip Ahmad');
    assert.equal(if301.nilai_angka, 95.0);
    assert.equal(if301.nilai_huruf, 'A');

    // 7. Verifikasi bahwa nilai yang sudah final sekarang tidak bisa diedit lagi
    const editPostFinal = await request(gatewayApp)
      .put('/nilai/1')
      .set('Authorization', `Bearer ${tokenDosen}`)
      .set('x-device-id', 'DEV-DOSEN-01')
      .set('x-simulated-hour', '11')
      .send({ nilai: 80.0 });

    assert.equal(editPostFinal.status, 403);
    assert.ok(editPostFinal.body.reason.includes('FINAL'));
  });
});

