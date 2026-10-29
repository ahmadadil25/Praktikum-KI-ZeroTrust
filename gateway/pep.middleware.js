const { verifyToken } = require('../shared/jwt');
const { getDb } = require('../shared/db');
const { recordAuditLog } = require('../shared/audit');
const { AUDIT_RESULT, HEADERS, ROLES } = require('../shared/constants');
const { evaluatePolicy } = require('./policy');

/**
 * Middleware Policy Enforcement Point (PEP)
 * Menginspeksi setiap request:
 * 1. Validasi keberadaan & keabsahan Token JWT (Access Token atau Service Token).
 * 2. Validasi X-Device-ID untuk request pengguna.
 * 3. Meminta evaluasi keputusan ke Policy Engine (PE/PA).
 * 4. Mencatat hasil Allow/Deny dan alasan detail ke audit_logs.
 * 5. Menolak request yang tidak memenuhi syarat keamanan.
 */
function enforcePolicy(req, res, next) {
  // Ambil full path (termasuk baseUrl Express jika di-mount pada sub-path)
  const fullPath = req.originalUrl ? req.originalUrl.split('?')[0] : ((req.baseUrl || '') + req.path);
  const endpoint = `${req.method.toUpperCase()} ${fullPath}`;
  const authHeader = req.headers[HEADERS.AUTHORIZATION] || req.headers['authorization'];
  const deviceIdHeader = req.headers[HEADERS.DEVICE_ID] || req.headers['x-device-id'] || null;
  const simulatedHourHeader = req.headers['x-simulated-hour'] || null;

  // 1. Ekstraksi Token dari Header Authorization
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    recordAuditLog({
      subject: 'anonymous',
      endpoint,
      deviceId: deviceIdHeader,
      hasil: AUDIT_RESULT.DENY,
      alasan: 'Header Authorization Bearer token wajib disertakan',
    });
    return res.status(401).json({
      error: 'Unauthorized',
      reason: 'Token autentikasi tidak ditemukan pada header Authorization: Bearer <token>',
    });
  }

  const rawToken = authHeader.substring(7).trim();
  const tokenVerification = verifyToken(rawToken);

  if (!tokenVerification.valid) {
    const isExpired = tokenVerification.expired;
    const alasan = isExpired
      ? 'Token telah kedaluwarsa'
      : 'Token tidak valid atau tanda tangan digital rusak';

    recordAuditLog({
      subject: 'unverified-token',
      endpoint,
      deviceId: deviceIdHeader,
      hasil: AUDIT_RESULT.DENY,
      alasan,
    });

    return res.status(401).json({
      error: isExpired ? 'Token Expired' : 'Invalid Token',
      reason: alasan,
    });
  }

  const userPayload = tokenVerification.payload;
  const subjectName = userPayload.username || userPayload.service || String(userPayload.sub);

  // 2. Verifikasi Device Binding untuk User Token
  if (tokenVerification.type === 'user') {
    if (!deviceIdHeader) {
      recordAuditLog({
        subject: subjectName,
        endpoint,
        deviceId: null,
        hasil: AUDIT_RESULT.DENY,
        alasan: 'Header X-Device-ID wajib disertakan untuk verifikasi identitas perangkat',
      });
      return res.status(400).json({
        error: 'Bad Request',
        reason: 'Header X-Device-ID wajib disertakan',
      });
    }

    const db = getDb();
    const registeredDevice = db.prepare(
      'SELECT * FROM devices WHERE user_id = ? AND device_id = ?'
    ).get(userPayload.sub, deviceIdHeader);

    if (!registeredDevice) {
      recordAuditLog({
        subject: subjectName,
        endpoint,
        deviceId: deviceIdHeader,
        hasil: AUDIT_RESULT.DENY,
        alasan: `Perangkat ${deviceIdHeader} tidak terdaftar untuk pengguna ${subjectName}`,
      });
      return res.status(403).json({
        error: 'Forbidden Device',
        reason: 'Perangkat tidak terdaftar untuk pengguna ini',
      });
    }

    if (registeredDevice.status !== 'active') {
      recordAuditLog({
        subject: subjectName,
        endpoint,
        deviceId: deviceIdHeader,
        hasil: AUDIT_RESULT.DENY,
        alasan: `Perangkat ${deviceIdHeader} berstatus ${registeredDevice.status}`,
      });
      return res.status(403).json({
        error: 'Inactive Device',
        reason: `Perangkat berstatus ${registeredDevice.status}`,
      });
    }
  }

  // 3. Evaluasi Kebijakan Akses (Policy Engine)
  const policyDecision = evaluatePolicy({
    user: userPayload,
    method: req.method,
    path: fullPath,
    params: req.params,
    body: req.body,
    simulatedHour: simulatedHourHeader,
  });

  if (!policyDecision.allowed) {
    recordAuditLog({
      subject: subjectName,
      endpoint,
      deviceId: deviceIdHeader || '-',
      hasil: AUDIT_RESULT.DENY,
      alasan: policyDecision.reason,
    });

    return res.status(policyDecision.statusCode).json({
      error: 'Access Denied',
      reason: policyDecision.reason,
    });
  }

  // 4. Catat Audit Log Keputusan ALLOW
  recordAuditLog({
    subject: subjectName,
    endpoint,
    deviceId: deviceIdHeader || '-',
    hasil: AUDIT_RESULT.ALLOW,
    alasan: policyDecision.reason,
  });

  // Lampirkan payload token dan token mentah ke request object
  req.user = userPayload;
  req.rawToken = rawToken;
  req.tokenType = tokenVerification.type;

  return next();
}

module.exports = {
  enforcePolicy,
};
