const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const config = require('./config');
const { ROLES } = require('./constants');

const TOKEN_ISSUER = 'zero-trust-gateway';

/**
 * Generate Access Token JWT (default 10 menit)
 */
function generateAccessToken(user, deviceId) {
  const payload = {
    sub: user.id,
    username: user.username,
    nama: user.nama,
    role: user.role,
    nim: user.nim || null,
    deviceId: deviceId,
  };

  return jwt.sign(payload, config.jwt.accessSecret, {
    expiresIn: config.jwt.accessExpiresIn,
    issuer: TOKEN_ISSUER,
  });
}

/**
 * Generate Refresh Token (Opaque Token acak 40 bytes)
 */
function generateRefreshToken() {
  return crypto.randomBytes(40).toString('hex');
}

/**
 * Hash token menggunakan SHA-256 untuk disimpan secara aman di database
 */
function hashToken(rawToken) {
  return crypto.createHash('sha256').update(rawToken).digest('hex');
}

/**
 * Generate Service Token JWT (default 5 menit) khusus untuk komunikasi antar-service
 */
function generateServiceToken(serviceName = 'service-nilai') {
  const payload = {
    sub: serviceName,
    role: ROLES.SERVICE,
    service: serviceName,
  };

  return jwt.sign(payload, config.jwt.serviceSecret, {
    expiresIn: config.jwt.serviceExpiresIn,
    issuer: TOKEN_ISSUER,
  });
}

/**
 * Verifikasi Access Token JWT
 */
function verifyAccessToken(token) {
  try {
    const payload = jwt.verify(token, config.jwt.accessSecret, {
      issuer: TOKEN_ISSUER,
    });
    return { valid: true, payload };
  } catch (error) {
    return {
      valid: false,
      expired: error.name === 'TokenExpiredError',
      error: error.message,
    };
  }
}

/**
 * Verifikasi Service Token JWT (tanda tangan, masa berlaku, penerbit, dan role service)
 */
function verifyServiceToken(token) {
  try {
    const payload = jwt.verify(token, config.jwt.serviceSecret, {
      issuer: TOKEN_ISSUER,
    });

    if (payload.role !== ROLES.SERVICE) {
      return {
        valid: false,
        expired: false,
        error: `Role token bukan service: '${payload.role}'`,
      };
    }

    return { valid: true, payload };
  } catch (error) {
    return {
      valid: false,
      expired: error.name === 'TokenExpiredError',
      error: error.message,
    };
  }
}

/**
 * Verifikasi token apa pun (Access Token atau Service Token)
 */
function verifyToken(token) {
  // Coba verifikasi sebagai User Access Token
  const accessResult = verifyAccessToken(token);
  if (accessResult.valid) {
    return { valid: true, type: 'user', payload: accessResult.payload };
  }

  // Jika gagal, coba verifikasi sebagai Service Token
  const serviceResult = verifyServiceToken(token);
  if (serviceResult.valid) {
    return { valid: true, type: 'service', payload: serviceResult.payload };
  }

  // Jika kedua verifikasi gagal
  return {
    valid: false,
    expired: accessResult.expired || serviceResult.expired,
    error: accessResult.error || serviceResult.error || 'Token tidak valid',
  };
}

module.exports = {
  TOKEN_ISSUER,
  generateAccessToken,
  generateRefreshToken,
  hashToken,
  generateServiceToken,
  verifyAccessToken,
  verifyServiceToken,
  verifyToken,
};
