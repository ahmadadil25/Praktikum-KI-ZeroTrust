-- ===================================================================
-- ZERO TRUST SISTEM NILAI - DATABASE SCHEMA (SQLite)
-- NIST SP 800-207 Architecture
-- ===================================================================

PRAGMA foreign_keys = ON;

-- 1. Tabel Pengguna (Users)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    nama TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'dosen', 'mahasiswa')),
    nim TEXT UNIQUE,
    created_at TEXT DEFAULT (datetime('now', 'localtime'))
);

-- 2. Tabel Perangkat Terdaftar (Devices)
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'blocked', 'revoked')),
    created_at TEXT DEFAULT (datetime('now', 'localtime')),
    UNIQUE(user_id, device_id)
);

-- 3. Tabel Kelas Akademik (Classes)
CREATE TABLE IF NOT EXISTS classes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kode_kelas TEXT UNIQUE NOT NULL,
    nama_kelas TEXT NOT NULL,
    mata_kuliah TEXT NOT NULL,
    dosen_id INTEGER NOT NULL REFERENCES users(id),
    sks INTEGER NOT NULL DEFAULT 3,
    created_at TEXT DEFAULT (datetime('now', 'localtime'))
);

-- 4. Tabel Nilai Mahasiswa (Grades)
CREATE TABLE IF NOT EXISTS grades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mahasiswa_id INTEGER NOT NULL REFERENCES users(id),
    kelas_id INTEGER NOT NULL REFERENCES classes(id) ON DELETE CASCADE,
    nilai REAL NOT NULL CHECK(nilai >= 0 AND nilai <= 100),
    status_final INTEGER NOT NULL DEFAULT 0 CHECK(status_final IN (0, 1)),
    updated_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    UNIQUE(mahasiswa_id, kelas_id)
);

-- 5. Tabel Transkrip Akademik (Transcripts)
CREATE TABLE IF NOT EXISTS transcripts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    mahasiswa_id INTEGER NOT NULL REFERENCES users(id),
    kelas_id INTEGER NOT NULL REFERENCES classes(id),
    kode_kelas TEXT NOT NULL,
    mata_kuliah TEXT NOT NULL,
    sks INTEGER NOT NULL DEFAULT 3,
    nilai_angka REAL NOT NULL,
    nilai_huruf TEXT NOT NULL,
    finalized_at TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    UNIQUE(mahasiswa_id, kelas_id)
);

-- 6. Tabel Refresh Tokens
CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    created_at TEXT DEFAULT (datetime('now', 'localtime'))
);

-- 7. Tabel Audit Log Gateway (Audit Logs)
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    waktu TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
    subject TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    device_id TEXT,
    hasil TEXT NOT NULL CHECK(hasil IN ('ALLOW', 'DENY')),
    alasan TEXT NOT NULL
);

-- Indeks untuk optimasi query Policy Engine
CREATE INDEX IF NOT EXISTS idx_devices_lookup ON devices(user_id, device_id, status);
CREATE INDEX IF NOT EXISTS idx_grades_mahasiswa ON grades(mahasiswa_id);
CREATE INDEX IF NOT EXISTS idx_grades_kelas ON grades(kelas_id);
CREATE INDEX IF NOT EXISTS idx_classes_dosen ON classes(dosen_id);
CREATE INDEX IF NOT EXISTS idx_audit_waktu ON audit_logs(waktu);

