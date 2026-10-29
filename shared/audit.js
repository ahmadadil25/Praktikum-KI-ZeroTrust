const { getDb } = require('./db');
const { AUDIT_RESULT } = require('./constants');
const { getWIBTimestamp } = require('./time');

/**
 * Filter sanitasi untuk memastikan tidak ada password, JWT, refresh token mentah,
 * atau secret yang tersimpan di dalam audit log (Prinsip Zero Trust A.7).
 */
function sanitizeLog(text) {
  if (!text) return '-';
  return String(text)
    .replace(/Bearer\s+[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/gi, 'Bearer [REDACTED_JWT]')
    .replace(/(password|secret|client_secret|refresh_token)\s*[:=]\s*["']?[^"',\s}]+/gi, '$1=[REDACTED]');
}

/**
 * Mencatat keputusan akses (Policy Decision) ke tabel audit_logs
 *
 * @param {Object} entry
 * @param {string} entry.subject - username, userId, atau nama service
 * @param {string} entry.endpoint - Metode HTTP dan path (cth: PUT /nilai/1)
 * @param {string} [entry.deviceId] - Device ID pengirim request
 * @param {'ALLOW'|'DENY'} entry.hasil - Hasil keputusan
 * @param {string} entry.alasan - Deskripsi alasan keputusan dibuat
 */
function recordAuditLog({ subject, endpoint, deviceId = null, hasil, alasan }) {
  try {
    const db = getDb();
    const waktu = getWIBTimestamp();
    const cleanSubject = sanitizeLog(subject || 'anonymous');
    const cleanEndpoint = sanitizeLog(endpoint || '-');
    const cleanDeviceId = deviceId ? sanitizeLog(deviceId) : '-';
    const cleanHasil = hasil === AUDIT_RESULT.ALLOW ? AUDIT_RESULT.ALLOW : AUDIT_RESULT.DENY;
    const cleanAlasan = sanitizeLog(alasan || '-');

    const stmt = db.prepare(`
      INSERT INTO audit_logs (waktu, subject, endpoint, device_id, hasil, alasan)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    stmt.run(waktu, cleanSubject, cleanEndpoint, cleanDeviceId, cleanHasil, cleanAlasan);

    // Logging ke console gateway
    const badge = cleanHasil === AUDIT_RESULT.ALLOW ? '\x1b[32m[ALLOW]\x1b[0m' : '\x1b[31m[DENY]\x1b[0m';
    console.log(`[AUDIT] ${waktu} | ${badge} ${cleanEndpoint} | Subj: ${cleanSubject} | Dev: ${cleanDeviceId} | ${cleanAlasan}`);
  } catch (error) {
    console.error('[AUDIT ERROR] Gagal menulis ke audit_logs:', error.message);
  }
}

module.exports = {
  recordAuditLog,
  sanitizeLog,
};
