const config = require('./config');
const { verifyToken } = require('./jwt');
const { HEADERS } = require('./constants');

/**
 * Middleware Keamanan Internal Resource Service (Defense in Depth)
 * Menerapkan prinsip Assume Breach & Never Trust, Always Verify:
 * 1. Menolak akses langsung yang tidak membawa X-Gateway-Secret yang sah.
 * 2. Memverifikasi ulang tanda tangan digital dan masa berlaku token JWT.
 * 3. Menolak akses jika secret valid tapi token tidak valid (Secret saja tidak cukup!).
 */
function verifyResourceSecurity(req, res, next) {
  // Abaikan pemeriksaan keamanan untuk endpoint operasional /health
  if (req.path === '/health' || req.path === '/health/') {
    return next();
  }

  const gatewaySecretHeader =
    req.headers[HEADERS.GATEWAY_SECRET] || req.headers['x-gateway-secret'];

  // 1. Verifikasi X-Gateway-Secret
  if (!gatewaySecretHeader || gatewaySecretHeader !== config.gatewaySecret) {
    return res.status(403).json({
      error: 'Direct Access Forbidden',
      reason: 'Akses langsung ke internal service ditolak. Request wajib melalui API Gateway dengan X-Gateway-Secret yang sah.',
    });
  }

  // 2. Verifikasi Token JWT
  const authHeader = req.headers[HEADERS.AUTHORIZATION] || req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({
      error: 'Unauthorized',
      reason: 'Header Authorization Bearer token wajib disertakan pada resource service',
    });
  }

  const rawToken = authHeader.substring(7).trim();
  const tokenVerification = verifyToken(rawToken);

  if (!tokenVerification.valid) {
    return res.status(401).json({
      error: tokenVerification.expired ? 'Token Expired' : 'Invalid Token',
      reason: `Verifikasi token pada resource service gagal: ${tokenVerification.error}`,
    });
  }

  // Token dan Gateway Secret sah
  req.user = tokenVerification.payload;
  req.tokenType = tokenVerification.type;
  req.rawToken = rawToken;

  return next();
}

module.exports = {
  verifyResourceSecurity,
};

