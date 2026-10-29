const bcrypt = require('bcryptjs');
const { getDb } = require('../shared/db');
const {
  generateAccessToken,
  generateRefreshToken,
  hashToken,
  generateServiceToken,
} = require('../shared/jwt');
const { recordAuditLog } = require('../shared/audit');
const { AUDIT_RESULT, HEADERS } = require('../shared/constants');
const config = require('../shared/config');

function getDeviceIdFromReq(req) {
  return (
    req.headers[HEADERS.DEVICE_ID] ||
    req.headers['x-device-id'] ||
    req.body.device_id ||
    req.body.deviceId ||
    null
  );
}

/**
 * POST /auth/login
 * Verifikasi kredensial & device binding pengguna
 */
function handleLogin(req, res) {
  const db = getDb();
  const { username, password } = req.body || {};
  const deviceId = getDeviceIdFromReq(req);
  const endpoint = 'POST /auth/login';

  if (!username || !password) {
    recordAuditLog({
      subject: username || 'anonymous',
      endpoint,
      deviceId,
      hasil: AUDIT_RESULT.DENY,
      alasan: 'Username dan password wajib diisi',
    });
    return res.status(400).json({
      error: 'Bad Request',
      reason: 'Username dan password wajib diisi',
    });
  }

  if (!deviceId) {
    recordAuditLog({
      subject: username,
      endpoint,
      deviceId: null,
      hasil: AUDIT_RESULT.DENY,
      alasan: 'Header X-Device-ID wajib disertakan untuk verifikasi identitas perangkat',
    });
    return res.status(400).json({
      error: 'Device Header Required',
      reason: 'Header X-Device-ID wajib disertakan',
    });
  }

  // 1. Cari user di database
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) {
    recordAuditLog({
      subject: username,
      endpoint,
      deviceId,
      hasil: AUDIT_RESULT.DENY,
      alasan: 'Kredensial tidak valid (pengguna tidak ditemukan)',
    });
    return res.status(401).json({
      error: 'Unauthorized',
      reason: 'Kredensial tidak valid',
    });
  }

  // 2. Verifikasi Password Hash
  const passwordMatch = bcrypt.compareSync(password, user.password_hash);
  if (!passwordMatch) {
    recordAuditLog({
      subject: username,
      endpoint,
      deviceId,
      hasil: AUDIT_RESULT.DENY,
      alasan: 'Kredensial tidak valid (kata sandi salah)',
    });
    return res.status(401).json({
      error: 'Unauthorized',
      reason: 'Kredensial tidak valid',
    });
  }

  // 3. Verifikasi Device Binding di database
  const registeredDevice = db.prepare(
    'SELECT * FROM devices WHERE user_id = ? AND device_id = ?'
  ).get(user.id, deviceId);

  if (!registeredDevice) {
    recordAuditLog({
      subject: username,
      endpoint,
      deviceId,
      hasil: AUDIT_RESULT.DENY,
      alasan: `Perangkat ${deviceId} tidak terdaftar untuk pengguna ${username}`,
    });
    return res.status(403).json({
      error: 'Forbidden Device',
      reason: 'Perangkat tidak terdaftar untuk pengguna ini',
    });
  }

  if (registeredDevice.status !== 'active') {
    recordAuditLog({
      subject: username,
      endpoint,
      deviceId,
      hasil: AUDIT_RESULT.DENY,
      alasan: `Perangkat ${deviceId} terdaftar namun berstatus ${registeredDevice.status}`,
    });
    return res.status(403).json({
      error: 'Inactive Device',
      reason: `Perangkat berstatus ${registeredDevice.status}`,
    });
  }

  // 4. Terbitkan Access Token (10 menit) dan Refresh Token (1 hari)
  const accessToken = generateAccessToken(user, deviceId);
  const rawRefreshToken = generateRefreshToken();
  const tokenHash = hashToken(rawRefreshToken);
  const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  db.prepare(`
    INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
    VALUES (?, ?, ?)
  `).run(user.id, tokenHash, expiresAt);

  recordAuditLog({
    subject: username,
    endpoint,
    deviceId,
    hasil: AUDIT_RESULT.ALLOW,
    alasan: 'Autentikasi berhasil; token akses dan refresh token diterbitkan',
  });

  return res.status(200).json({
    status: 'success',
    message: 'Login berhasil',
    token_type: 'Bearer',
    access_token: accessToken,
    refresh_token: rawRefreshToken,
    expires_in: 600,
    user: {
      id: user.id,
      username: user.username,
      nama: user.nama,
      role: user.role,
      nim: user.nim,
    },
    device_id: deviceId,
  });
}

/**
 * POST /auth/refresh
 * Validasi refresh token, kedaluwarsa, status revoke, & device
 */
function handleRefresh(req, res) {
  const db = getDb();
  const { refresh_token } = req.body || {};
  const deviceId = getDeviceIdFromReq(req);
  const endpoint = 'POST /auth/refresh';

  if (!refresh_token) {
    recordAuditLog({
      subject: 'anonymous',
      endpoint,
      deviceId,
      hasil: AUDIT_RESULT.DENY,
      alasan: 'Refresh token wajib disertakan',
    });
    return res.status(400).json({
      error: 'Bad Request',
      reason: 'Refresh token wajib disertakan',
    });
  }

  if (!deviceId) {
    recordAuditLog({
      subject: 'anonymous',
      endpoint,
      deviceId: null,
      hasil: AUDIT_RESULT.DENY,
      alasan: 'Header X-Device-ID wajib disertakan saat refresh token',
    });
    return res.status(400).json({
      error: 'Bad Request',
      reason: 'Header X-Device-ID wajib disertakan',
    });
  }

  const tokenHash = hashToken(refresh_token);
  const tokenRecord = db.prepare(`
    SELECT rt.*, u.id as user_id, u.username, u.nama, u.role, u.nim
    FROM refresh_tokens rt
    JOIN users u ON rt.user_id = u.id
    WHERE rt.token_hash = ?
  `).get(tokenHash);

  if (!tokenRecord) {
    recordAuditLog({
      subject: 'anonymous',
      endpoint,
      deviceId,
      hasil: AUDIT_RESULT.DENY,
      alasan: 'Refresh token tidak valid atau tidak ditemukan di database',
    });
    return res.status(401).json({
      error: 'Unauthorized',
      reason: 'Refresh token tidak valid',
    });
  }

  // Cek apakah sudah dicabut (revoked)
  if (tokenRecord.revoked_at) {
    recordAuditLog({
      subject: tokenRecord.username,
      endpoint,
      deviceId,
      hasil: AUDIT_RESULT.DENY,
      alasan: 'Refresh token telah dicabut (revoked)',
    });
    return res.status(401).json({
      error: 'Unauthorized',
      reason: 'Refresh token telah dicabut',
    });
  }

  // Cek kedaluwarsa
  if (new Date(tokenRecord.expires_at) < new Date()) {
    recordAuditLog({
      subject: tokenRecord.username,
      endpoint,
      deviceId,
      hasil: AUDIT_RESULT.DENY,
      alasan: 'Refresh token telah kedaluwarsa',
    });
    return res.status(401).json({
      error: 'Unauthorized',
      reason: 'Refresh token telah kedaluwarsa',
    });
  }

  // Validasi device terdaftar
  const registeredDevice = db.prepare(
    'SELECT * FROM devices WHERE user_id = ? AND device_id = ?'
  ).get(tokenRecord.user_id, deviceId);

  if (!registeredDevice || registeredDevice.status !== 'active') {
    recordAuditLog({
      subject: tokenRecord.username,
      endpoint,
      deviceId,
      hasil: AUDIT_RESULT.DENY,
      alasan: `Perangkat ${deviceId} tidak valid untuk refresh token pengguna ${tokenRecord.username}`,
    });
    return res.status(403).json({
      error: 'Forbidden Device',
      reason: 'Perangkat tidak terdaftar atau tidak aktif',
    });
  }

  // Revoke token lama dan terbitkan pasangan token baru (Token Rotation)
  db.prepare(`
    UPDATE refresh_tokens
    SET revoked_at = datetime('now', 'localtime')
    WHERE id = ?
  `).run(tokenRecord.id);

  const user = {
    id: tokenRecord.user_id,
    username: tokenRecord.username,
    nama: tokenRecord.nama,
    role: tokenRecord.role,
    nim: tokenRecord.nim,
  };

  const newAccessToken = generateAccessToken(user, deviceId);
  const newRefreshToken = generateRefreshToken();
  const newTokenHash = hashToken(newRefreshToken);
  const newExpiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();

  db.prepare(`
    INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
    VALUES (?, ?, ?)
  `).run(user.id, newTokenHash, newExpiresAt);

  recordAuditLog({
    subject: user.username,
    endpoint,
    deviceId,
    hasil: AUDIT_RESULT.ALLOW,
    alasan: 'Refresh token valid; token akses dan refresh baru berhasil diterbitkan',
  });

  return res.status(200).json({
    status: 'success',
    message: 'Token berhasil diperbarui',
    token_type: 'Bearer',
    access_token: newAccessToken,
    refresh_token: newRefreshToken,
    expires_in: 600,
  });
}

/**
 * POST /auth/logout
 * Cabut refresh token di database
 */
function handleLogout(req, res) {
  const db = getDb();
  const { refresh_token } = req.body || {};
  const deviceId = getDeviceIdFromReq(req);
  const endpoint = 'POST /auth/logout';

  if (!refresh_token) {
    recordAuditLog({
      subject: 'anonymous',
      endpoint,
      deviceId,
      hasil: AUDIT_RESULT.DENY,
      alasan: 'Refresh token wajib disertakan untuk logout',
    });
    return res.status(400).json({
      error: 'Bad Request',
      reason: 'Refresh token wajib disertakan untuk logout',
    });
  }

  const tokenHash = hashToken(refresh_token);
  const tokenRecord = db.prepare(`
    SELECT rt.*, u.username
    FROM refresh_tokens rt
    JOIN users u ON rt.user_id = u.id
    WHERE rt.token_hash = ?
  `).get(tokenHash);

  if (!tokenRecord) {
    recordAuditLog({
      subject: 'anonymous',
      endpoint,
      deviceId,
      hasil: AUDIT_RESULT.DENY,
      alasan: 'Refresh token tidak ditemukan di database',
    });
    return res.status(404).json({
      error: 'Not Found',
      reason: 'Refresh token tidak ditemukan',
    });
  }

  db.prepare(`
    UPDATE refresh_tokens
    SET revoked_at = datetime('now', 'localtime')
    WHERE id = ?
  `).run(tokenRecord.id);

  recordAuditLog({
    subject: tokenRecord.username,
    endpoint,
    deviceId,
    hasil: AUDIT_RESULT.ALLOW,
    alasan: 'Logout berhasil; refresh token dicabut (revoked)',
  });

  return res.status(200).json({
    status: 'success',
    message: 'Logout berhasil, refresh token telah dicabut',
  });
}

/**
 * POST /auth/service
 * Penerbitan Service Token (5 menit) khusus untuk Service Nilai
 */
function handleServiceToken(req, res) {
  const { client_id, client_secret } = req.body || {};
  const endpoint = 'POST /auth/service';

  if (!client_id || !client_secret) {
    recordAuditLog({
      subject: client_id || 'anonymous-service',
      endpoint,
      deviceId: '-',
      hasil: AUDIT_RESULT.DENY,
      alasan: 'Client ID dan Client Secret wajib disertakan',
    });
    return res.status(400).json({
      error: 'Bad Request',
      reason: 'Client ID dan Client Secret wajib disertakan',
    });
  }

  // Verifikasi kecocokan Client ID dan Secret
  if (
    client_id !== config.serviceAuth.clientId ||
    client_secret !== config.serviceAuth.clientSecret
  ) {
    recordAuditLog({
      subject: client_id,
      endpoint,
      deviceId: '-',
      hasil: AUDIT_RESULT.DENY,
      alasan: 'Kredensial client service tidak valid',
    });
    return res.status(401).json({
      error: 'Unauthorized',
      reason: 'Kredensial client service tidak valid',
    });
  }

  const serviceToken = generateServiceToken(client_id);

  recordAuditLog({
    subject: client_id,
    endpoint,
    deviceId: '-',
    hasil: AUDIT_RESULT.ALLOW,
    alasan: 'Service token berhasil diterbitkan dengan masa berlaku 5 menit (role: service)',
  });

  return res.status(200).json({
    status: 'success',
    message: 'Service token berhasil diterbitkan',
    token_type: 'Bearer',
    access_token: serviceToken,
    expires_in: 300,
    role: 'service',
  });
}

module.exports = {
  handleLogin,
  handleRefresh,
  handleLogout,
  handleServiceToken,
};
