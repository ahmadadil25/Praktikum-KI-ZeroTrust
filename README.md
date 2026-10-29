# Zero Trust Sistem Nilai Akademik
> Implementasi Arsitektur Keamanan Zero Trust (NIST SP 800-207) pada Sistem Pengelolaan Nilai Akademik.  
> Tugas Praktikum Individu Keamanan Informasi (KP70065004) · Informatika Universitas Siliwangi.

---

## 1. Arsitektur Sistem & Prinsip Zero Trust

Sistem ini menerapkan prinsip-prinsip inti Zero Trust (NIST SP 800-207):
1. **Never Trust, Always Verify**: Tidak ada zona internal yang dipercaya secara implisit. Setiap request diperiksa di Policy Enforcement Point (API Gateway) terhadap kebijakan kontekstual (identitas, peran, device binding, jam operasional). Di tingkat resource service (Service Nilai dan Service Transkrip), diterapkan **Defense in Depth**: service memverifikasi ulang header rahasia `X-Gateway-Secret` DAN tanda tangan serta masa berlaku token JWT.
2. **Least Privilege**: Pembatasan hak akses berbasis peran (RBAC) dan atribut database aktual (ABAC):
   - Mahasiswa hanya dapat melihat nilai dan transkrip miliknya sendiri.
   - Dosen hanya dapat melihat dan mengubah nilai pada kelas yang diampunya, serta hanya untuk nilai yang belum difinalisasi.
   - Admin hanya dapat melihat transkrip seluruh mahasiswa.
   - Endpoint sinkronisasi transkrip hanya dapat diakses menggunakan Service Token sah dari Service Nilai.
3. **Assume Breach**: Durasi token dibuat singkat (Access Token: 10 menit, Service Token: 5 menit). Refresh token disimpan ter-hash (SHA-256) di database dan mendukung pencabutan instan (revocation). Akses langsung ke service internal tanpa melalui Gateway ditolak.

```
                      +-------------------+
                      | Client            |
                      | (Postman / curl)  |
                      +---------+---------+
                                | access token + X-Device-ID
                                v
+------------------+  allow/deny +--------------------------+
| Policy Engine /  |<----------> | API Gateway (PEP)        | --------> [ Audit Log ]
| Administrator    |             | Port 3000                |           (Database)
| (PE/PA)          |             +-------------+------------+
+--------+---------+                           |
         |                                     | + X-Gateway-Secret
         | baca atribut                        |
         v                                     +--------------------+
+------------------+                           |                    |
| Shared Database  |<--------------+-----------+--------+           |
| (SQLite)         |               |                    |           |
+------------------+               v                    v           v
                          +-----------------+  sinkron  +--------------------+
                          | Service Nilai   |---------> | Service Transkrip  |
                          | Port 3001       |  (via PEP)| Port 3002          |
                          | (verifikasi     |           | (verifikasi        |
                          |  secret+token)  |           |  secret+token)     |
                          +-----------------+           +--------------------+
```

### Komponen Sistem
| Komponen | Peran (NIST SP 800-207) | Port | Tanggung Jawab |
|---|---|---|---|
| **API Gateway** | Policy Enforcement Point (PEP) | `3000` | Satu-satunya gerbang masuk client. Meminta otorisasi ke Policy Engine, mencatat audit log, menyisipkan `X-Gateway-Secret`, dan meneruskan request yang sah. |
| **Policy Engine / PA** | Policy Engine / Policy Admin | Terintegrasi di Gateway | Mengelola login, verifikasi device terdaftar, evaluasi aturan ABAC dari database, dan jam akses. |
| **Service Nilai** | Resource Service | `3001` | Mengelola data nilai dan kelas mahasiswa. Memverifikasi `X-Gateway-Secret` dan token. Mengirim request sinkronisasi ke Service Transkrip via Gateway saat finalisasi nilai. |
| **Service Transkrip** | Resource Service | `3002` | Mengelola transkrip akademik mahasiswa. Memverifikasi `X-Gateway-Secret` dan token. Endpoint sinkronisasi hanya menerima token dengan `role: service`. |
| **Database** | Shared Resource | SQLite (`data/database.sqlite`) | Database bersama untuk persistensi pengguna, perangkat, kelas, nilai, transkrip, refresh token, dan audit log. |

---

## 2. Tabel Kebijakan Akses (Policy Decision)

| Endpoint | Method | Ditangani oleh | Role yang Diizinkan | Kondisi Akses & Aturan Zero Trust |
|---|---|---|---|---|
| `/auth/login` | `POST` | Gateway | Semua user | Kredensial valid dan `X-Device-ID` terdaftar & aktif |
| `/auth/refresh` | `POST` | Gateway | Semua user | Refresh token valid, belum dicabut, dan device terdaftar |
| `/auth/logout` | `POST` | Gateway | Semua user | Refresh token dicabut (revoked) di database |
| `/auth/service` | `POST` | Gateway | Service Nilai | Client ID dan Client Secret khusus Service Nilai valid |
| `/nilai` | `GET` | Service Nilai | Mahasiswa, Dosen | Mahasiswa: hanya nilai miliknya. Dosen: hanya kelas yang diampunya |
| `/nilai/:id` | `PUT` | Service Nilai | Dosen | Kelas yang diampu, nilai belum final, dan dalam jam akses (07.00–21.00 WIB) |
| `/kelas/:id/finalisasi` | `POST` | Service Nilai | Dosen | Kelas yang diampu dan dalam jam akses (07.00–21.00 WIB). Memanggil sinkronisasi via Gateway |
| `/transkrip/:nim` | `GET` | Service Transkrip | Mahasiswa, Admin | Mahasiswa: hanya NIM miliknya. Admin: semua NIM |
| `/transkrip/sinkron` | `POST` | Service Transkrip | Service Nilai | Hanya menerima Service Token (`role: service`). Token pengguna ditolak |

---

## 3. Akun Demo & Perangkat Terdaftar

Semua akun demo menggunakan password default praktikum:
```
Password123!
```
*(Tersimpan dalam bentuk hash `bcrypt` di database, bukan plain text).*

| Username | Nama Lengkap | Role | NIM | Device ID Terdaftar | Keterangan & Hak Akses |
|---|---|---|---|---|---|
| `admin1` | Administrator Sistem | `admin` | `-` | `DEV-ADMIN-01` | Melihat transkrip semua mahasiswa |
| `dosen_budi` | Dr. Budi Hartono, M.Kom. | `dosen` | `-` | `DEV-DOSEN-01` | Dosen pengampu kelas `IF-301` (Keamanan Informasi) |
| `dosen_siti` | Siti Rahma, M.T. | `dosen` | `-` | `DEV-DOSEN-02` | Dosen pengampu kelas `IF-302` (Sistem Terdistribusi) |
| `mhs_ahmad` | Ahmad Pratama | `mahasiswa` | `220101` | `DEV-MHS-01` | Terdaftar di `IF-301` (draft) dan `IF-302` (final) |
| `mhs_bambang` | Bambang Wijaya | `mahasiswa` | `220102` | `DEV-MHS-02` | Terdaftar di `IF-301` (draft) |
| `mhs_citra` | Citra Dewi | `mahasiswa` | `220103` | `DEV-MHS-03` | Terdaftar di `IF-302` (draft) |

---

## 4. Struktur Direktori Proyek

```
zero-trust-sistem-nilai/
├── .env                          # Konfigurasi environment lokal (diabaikan git)
├── .env.example                  # Template variabel environment
├── .gitignore                    # Mengabaikan .env, node_modules, dan file *.sqlite
├── package.json                  # Dependensi dan skrip proyek
├── README.md                     # Dokumentasi arsitektur dan panduan
├── IMPLEMENTATION_PLAN.md        # Rencana bertahap implementasi Zero Trust
├── database/
│   ├── schema.sql                # DDL 7 tabel (users, devices, classes, grades, transcripts, refresh_tokens, audit_logs)
│   ├── seed.js                   # Skrip seed data awal (idempotent)
│   └── reset.js                  # Skrip pembersihan dan seeding ulang database
├── shared/
│   ├── config.js                 # Loader konfigurasi berbasis dotenv
│   ├── constants.js              # Definisi konstanta role, status, dan header
│   ├── db.js                     # Koneksi SQLite bersama (better-sqlite3)
│   ├── jwt.js                    # Utilitas penerbitan & verifikasi token (access, refresh, service)
│   ├── time.js                   # Utilitas jam akses 07.00-21.00 WIB (Asia/Jakarta)
│   ├── audit.js                  # Utilitas pencatatan keputusan PEP ke audit_logs
│   └── verify-resource-security.js # Middleware keamanan internal service (Defense in Depth)
├── gateway/
│   ├── app.js                    # Express app API Gateway / PEP
│   ├── server.js                 # Server entrypoint API Gateway (port 3000)
│   ├── auth.controller.js        # Controller login, refresh, logout, dan service token
│   ├── policy.js                 # Policy Engine: evaluasi aturan akses ABAC & konteks
│   ├── pep.middleware.js         # PEP Interceptor: validasi token, device binding, audit logging
│   └── proxy.js                  # Forwarding request ke service internal dengan X-Gateway-Secret
├── service-nilai/
│   ├── app.js                    # Express app Service Nilai (port 3001)
│   └── server.js                 # Server entrypoint Service Nilai
├── service-transkrip/
│   ├── app.js                    # Express app Service Transkrip (port 3002)
│   └── server.js                 # Server entrypoint Service Transkrip
├── scripts/
│   └── start-all.js              # Runner untuk menjalankan ketiga service secara bersamaan
└── tests/
    ├── foundation.test.js        # Pengujian fondasi, database, & health check
    ├── auth.test.js              # Pengujian login, refresh, logout, device, dan service token
    ├── policy-zero-trust.test.js # Pengujian komprehensif kontrol akses Zero Trust & negative cases
    └── e2e-flow.test.js          # Pengujian alur lengkap integrasi sistem (E2E)
```

---

## 5. Cara Instalasi & Menjalankan Aplikasi

### 1. Instalasi Dependensi
```bash
npm install
```

### 2. Inisialisasi Database
Jalankan skrip seed database awal:
```bash
npm run seed
```
*(Atau gunakan `npm run reset` jika ingin membersihkan database dan memulai dari kondisi awal).*

### 3. Menjalankan Layanan
Jalankan ketiga layanan sekaligus melalui root runner:
```bash
npm start
```
*Layanan berjalan pada: Gateway (`http://localhost:3000`), Service Nilai (`http://localhost:3001`), Service Transkrip (`http://localhost:3002`).*

---

## 6. Panduan Pengujian API Manual (cURL / Postman)

### 1. Login Pengguna (Mahasiswa / Dosen / Admin)
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: DEV-DOSEN-01" \
  -d '{"username": "dosen_budi", "password": "Password123!"}'
```
*Respon: `access_token` (10 menit) dan `refresh_token` (1 hari).*

### 2. Memperbarui Nilai Mahasiswa (Hanya Dosen Pengampu & Dalam Jam Akses)
```bash
curl -X PUT http://localhost:3000/nilai/1 \
  -H "Authorization: Bearer <ACCESS_TOKEN_DOSEN>" \
  -H "X-Device-ID: DEV-DOSEN-01" \
  -H "Content-Type: application/json" \
  -d '{"nilai": 92.5}'
```

### 3. Finalisasi Nilai Kelas
```bash
curl -X POST http://localhost:3000/kelas/1/finalisasi \
  -H "Authorization: Bearer <ACCESS_TOKEN_DOSEN>" \
  -H "X-Device-ID: DEV-DOSEN-01"
```

### 4. Melihat Transkrip Mahasiswa
```bash
# Mahasiswa melihat transkripnya sendiri
curl -X GET http://localhost:3000/transkrip/220101 \
  -H "Authorization: Bearer <ACCESS_TOKEN_AHMAD>" \
  -H "X-Device-ID: DEV-MHS-01"

# Admin melihat transkrip mahasiswa mana pun
curl -X GET http://localhost:3000/transkrip/220101 \
  -H "Authorization: Bearer <ACCESS_TOKEN_ADMIN>" \
  -H "X-Device-ID: DEV-ADMIN-01"
```

### 5. Refresh Token
```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: DEV-DOSEN-01" \
  -d '{"refresh_token": "<REFRESH_TOKEN>"}'
```

### 6. Logout (Pencabutan Refresh Token)
```bash
curl -X POST http://localhost:3000/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<REFRESH_TOKEN>"}'
```

---

## 7. Pengujian Otomatis (Automated Tests)

Jalankan seluruh rangkaian uji coba:
```bash
npm test
```

### Ringkasan Cakupan Pengujian:
1. **Health Check & Fondasi Database**: Verifikasi 3 service aktif, verifikasi 6 akun demo dengan password hash bcrypt, verifikasi 6 device aktif, verifikasi 2 kelas dan pemisahan pengampu.
2. **Autentikasi & Token Management**:
   - Login berhasil dengan kredensial & device terdaftar.
   - Penolakan login jika password salah, username tidak ditemukan, tanpa header `X-Device-ID`, atau device tidak terdaftar/diblokir.
   - Refresh token rotasi berhasil dan ditolak jika menggunakan device tidak terdaftar atau token yang telah dicabut (logout).
   - Penerbitan Service Token 5 menit (`role: service`) dan penolakan kredensial service yang salah.
3. **Kebijakan Akses Zero Trust (NIST SP 800-207)**:
   - Penolakan request dengan token kedaluwarsa atau tanpa otorisasi.
   - Penolakan mahasiswa mengakses transkrip mahasiswa lain.
   - Penolakan dosen mengubah nilai atau memfinalisasi kelas yang bukan tanggung jawabnya.
   - Penolakan perubahan nilai di luar jam operasional (07.00 - 21.00 WIB) dan **verifikasi bahwa nilai di database tidak berubah**.
   - Penolakan perubahan nilai yang sudah berstatus FINAL.
   - Penolakan akses langsung ke Service Nilai & Service Transkrip tanpa `X-Gateway-Secret` atau tanpa token yang sah.
   - Penolakan token pengguna (mahasiswa, dosen, admin) pada endpoint sinkronisasi transkrip `/transkrip/sinkron`.
4. **Alur End-to-End**:
   - Dosen login -> input nilai -> finalisasi kelas -> pemanggilan antar-service otomatis menggunakan Service Token -> mahasiswa cek transkrip yang tersinkronkan.
5. **Audit Logging**:
   - Memverifikasi bahwa setiap keputusan akses (ALLOW dan DENY) tercatat secara permanen di tabel `audit_logs` beserta waktu, subjek, endpoint, device, hasil, dan alasan detail.
