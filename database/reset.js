const { getDb } = require('../shared/db');
const { runSeed } = require('./seed');

function resetDatabase() {
  const db = getDb();
  console.log('[RESET] Menghapus semua tabel...');
  db.exec(`
    PRAGMA foreign_keys = OFF;
    DROP TABLE IF EXISTS audit_logs;
    DROP TABLE IF EXISTS refresh_tokens;
    DROP TABLE IF EXISTS transcripts;
    DROP TABLE IF EXISTS grades;
    DROP TABLE IF EXISTS classes;
    DROP TABLE IF EXISTS devices;
    DROP TABLE IF EXISTS users;
    PRAGMA foreign_keys = ON;
  `);
  console.log('[RESET] Menjalankan kembali migrasi dan seed...');
  runSeed(db);
  console.log('[RESET] Database berhasil di-reset dan di-seed ulang.');
}

if (require.main === module) {
  try {
    resetDatabase();
    process.exit(0);
  } catch (err) {
    console.error('[RESET] Terjadi kesalahan saat reset database:', err);
    process.exit(1);
  }
}

module.exports = { resetDatabase };
