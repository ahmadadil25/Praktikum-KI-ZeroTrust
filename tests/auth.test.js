const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const jwt = require('jsonwebtoken');

const gatewayApp = require('../gateway/app');
const { getDb, closeDb } = require('../shared/db');
const { runSeed } = require('../database/seed');
const config = require('../shared/config');
const { ROLES } = require('../shared/constants');

describe('Tahap 2: Autentikasi, Token Management, & Device Binding', () => {
  let db;

  before(() => {
    db = getDb();
    runSeed(db);
  });

  after(() => {
    closeDb();
  });

  describe('POST /auth/login', () => {
    it('Login berhasil dengan kredensial valid dan X-Device-ID terdaftar', async () => {
      const res = await request(gatewayApp)
        .post('/auth/login')
        .set('x-device-id', 'DEV-DOSEN-01')
        .send({
          username: 'dosen_budi',
          password: 'Password123!',
        });

      assert.equal(res.status, 200);
      assert.equal(res.body.status, 'success');
      assert.ok(res.body.access_token);
      assert.ok(res.body.refresh_token);
      assert.equal(res.body.user.username, 'dosen_budi');
      assert.equal(res.body.user.role, ROLES.DOSEN);

      // Verifikasi payload JWT access token (10 menit)
      const decoded = jwt.verify(res.body.access_token, config.jwt.accessSecret);
      assert.equal(decoded.username, 'dosen_budi');
      assert.equal(decoded.role, ROLES.DOSEN);
      assert.equal(decoded.deviceId, 'DEV-DOSEN-01');
      assert.ok(decoded.exp - decoded.iat <= 600, 'Access token harus berlaku maksimal 10 menit');
    });

    it('Login ditolak jika password salah', async () => {
      const res = await request(gatewayApp)
        .post('/auth/login')
        .set('x-device-id', 'DEV-DOSEN-01')
        .send({
          username: 'dosen_budi',
          password: 'WrongPassword!',
        });

      assert.equal(res.status, 401);
      assert.equal(res.body.error, 'Unauthorized');
    });

    it('Login ditolak jika username tidak ditemukan', async () => {
      const res = await request(gatewayApp)
        .post('/auth/login')
        .set('x-device-id', 'DEV-DOSEN-01')
        .send({
          username: 'user_tidak_ada',
          password: 'Password123!',
        });

      assert.equal(res.status, 401);
      assert.equal(res.body.error, 'Unauthorized');
    });

    it('Login ditolak jika header X-Device-ID tidak disertakan', async () => {
      const res = await request(gatewayApp)
        .post('/auth/login')
        .send({
          username: 'dosen_budi',
          password: 'Password123!',
        });

      assert.equal(res.status, 400);
      assert.ok(res.body.reason.includes('X-Device-ID'));
    });

    it('Login ditolak jika device ID tidak terdaftar untuk user tersebut', async () => {
      const res = await request(gatewayApp)
        .post('/auth/login')
        .set('x-device-id', 'DEV-UNKNOWN-999')
        .send({
          username: 'dosen_budi',
          password: 'Password123!',
        });

      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'Forbidden Device');
    });

    it('Login ditolak jika device terdaftar tetapi berstatus diblokir', async () => {
      // Blokir sementara device DEV-MHS-03
      db.prepare("UPDATE devices SET status = 'blocked' WHERE device_id = 'DEV-MHS-03'").run();

      const res = await request(gatewayApp)
        .post('/auth/login')
        .set('x-device-id', 'DEV-MHS-03')
        .send({
          username: 'mhs_citra',
          password: 'Password123!',
        });

      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'Inactive Device');

      // Kembalikan status
      db.prepare("UPDATE devices SET status = 'active' WHERE device_id = 'DEV-MHS-03'").run();
    });
  });

  describe('POST /auth/refresh & POST /auth/logout', () => {
    let refreshToken;
    const deviceId = 'DEV-MHS-01';

    before(async () => {
      const loginRes = await request(gatewayApp)
        .post('/auth/login')
        .set('x-device-id', deviceId)
        .send({
          username: 'mhs_ahmad',
          password: 'Password123!',
        });
      refreshToken = loginRes.body.refresh_token;
    });

    it('Refresh token berhasil menerbitkan access token baru', async () => {
      const res = await request(gatewayApp)
        .post('/auth/refresh')
        .set('x-device-id', deviceId)
        .send({ refresh_token: refreshToken });

      assert.equal(res.status, 200);
      assert.equal(res.body.status, 'success');
      assert.ok(res.body.access_token);
      assert.ok(res.body.refresh_token, 'Harus menerbitkan pasangan refresh token rotasi baru');

      // Update refreshToken untuk pengujian berikutnya
      refreshToken = res.body.refresh_token;
    });

    it('Refresh token ditolak jika menggunakan device yang tidak terdaftar', async () => {
      const res = await request(gatewayApp)
        .post('/auth/refresh')
        .set('x-device-id', 'DEV-UNKNOWN-X')
        .send({ refresh_token: refreshToken });

      assert.equal(res.status, 403);
      assert.equal(res.body.error, 'Forbidden Device');
    });

    it('Logout berhasil mencabut (revoke) refresh token di database', async () => {
      const res = await request(gatewayApp)
        .post('/auth/logout')
        .send({ refresh_token: refreshToken });

      assert.equal(res.status, 200);
      assert.equal(res.body.status, 'success');
    });

    it('Refresh token yang telah dicabut (logout) tidak dapat digunakan lagi', async () => {
      const res = await request(gatewayApp)
        .post('/auth/refresh')
        .set('x-device-id', deviceId)
        .send({ refresh_token: refreshToken });

      assert.equal(res.status, 401);
      assert.ok(res.body.reason.includes('dicabut'));
    });
  });

  describe('POST /auth/service', () => {
    it('Menerbitkan Service Token 5 menit untuk Client ID & Secret yang valid', async () => {
      const res = await request(gatewayApp)
        .post('/auth/service')
        .send({
          client_id: config.serviceAuth.clientId,
          client_secret: config.serviceAuth.clientSecret,
        });

      assert.equal(res.status, 200);
      assert.equal(res.body.status, 'success');
      assert.equal(res.body.role, 'service');
      assert.ok(res.body.access_token);

      const decoded = jwt.verify(res.body.access_token, config.jwt.serviceSecret);
      assert.equal(decoded.role, ROLES.SERVICE);
      assert.ok(decoded.exp - decoded.iat <= 300, 'Service token berlaku 5 menit');
    });

    it('Menolak penerbitan Service Token jika client secret salah', async () => {
      const res = await request(gatewayApp)
        .post('/auth/service')
        .send({
          client_id: config.serviceAuth.clientId,
          client_secret: 'invalid-secret-key',
        });

      assert.equal(res.status, 401);
      assert.equal(res.body.error, 'Unauthorized');
    });
  });
});
