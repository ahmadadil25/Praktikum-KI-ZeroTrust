const { getDb } = require('./db');
const { AUDIT_RESULT } = require('./constants');
const { getWIBTimestamp } = require('./time');

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
    const cleanSubject = String(subject || 'anonymous');
    const cleanEndpoint = String(endpoint || '-');
    const cleanDeviceId = deviceId ? String(deviceId) : '-';
    const cleanHasil = hasil === AUDIT_RESULT.ALLOW ? AUDIT_RESULT.ALLOW : AUDIT_RESULT.DENY;
    const cleanAlasan = String(alasan || '-');

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
};
