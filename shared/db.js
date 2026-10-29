const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const config = require('./config');

let dbInstance = null;

function getDb(customPath = null) {
  if (dbInstance && !customPath) {
    return dbInstance;
  }

  const resolvedPath = customPath || config.dbPath;

  // Pastikan direktori folder database ada
  if (resolvedPath !== ':memory:') {
    const dir = path.dirname(resolvedPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  const db = new Database(resolvedPath);
  db.pragma('journal_mode = WAL');
  db.pragma('foreign_keys = ON');

  // Inisialisasi skema jika tabel users belum ada
  const schemaPath = path.resolve(__dirname, '../database/schema.sql');
  if (fs.existsSync(schemaPath)) {
    const tableExists = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
    ).get();
    if (!tableExists) {
      const schemaSql = fs.readFileSync(schemaPath, 'utf8');
      db.exec(schemaSql);
    }
  }

  if (!customPath) {
    dbInstance = db;
  }

  return db;
}

function closeDb() {
  if (dbInstance) {
    try {
      dbInstance.close();
    } catch (err) {
      // Abaikan jika sudah tertutup
    }
    dbInstance = null;
  }
}

module.exports = {
  getDb,
  closeDb,
};
