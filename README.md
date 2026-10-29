# Zero Trust Sistem Nilai Akademik
> Implementasi Arsitektur Keamanan Zero Trust (NIST SP 800-207) pada Sistem Pengelolaan Nilai Akademik.  
> Tugas Praktikum Individu Keamanan Informasi (KP70065004) · Informatika Universitas Siliwangi.

---

## 1. Arsitektur Sistem & Prinsip Zero Trust

Sistem ini menerapkan tiga pilar utama Zero Trust:
1. **Never Trust, Always Verify**: Tidak ada zona jaringan internal yang dipercaya secara implisit. Setiap panggilan masuk ke API Gateway diperiksa terhadap policy context (identitas, peran, device binding, jam operasional). Setiap panggilan internal ke resource service (Service Nilai dan Service Transkrip) wajib menyertakan verifikasi token dan `X-Gateway-Secret`.
2. **Least Privilege**: Pengguna hanya diberikan hak akses minimum sesuai perannya (Mahasiswa hanya melihat nilai miliknya, Dosen hanya mengakses kelas yang diampunya dan nilai yang belum final, Admin hanya dapat membaca transkrip).
3. **Assume Breach**: Durasi token dibatasi singkat (Access token: 10 menit, Service token: 5 menit). Refresh token disimpan ter-hash di database dan dapat dicabut instan. Pemanggilan antar-service Service Nilai ke Service Transkrip wajib melalui API Gateway menggunakan service token terverifikasi.

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
| **Policy Engine / PA** | Policy Engine / Policy Admin | Terintegrasi di Gateway | Mengelola login, verifikasi device terdaftar, evaluasi aturan berbasis atribut (ABAC) dari database, dan jam akses. |
| **Service Nilai** | Resource Service | `3001` | Mengelola data nilai dan kelas mahasiswa. Memverifikasi `X-Gateway-Secret` dan token. Mengirim request sinkronisasi ke Service Transkrip via Gateway saat finalisasi nilai. |
| **Service Transkrip** | Resource Service | `3002` | Mengelola transkrip akademik mahasiswa. Memverifikasi `X-Gateway-Secret` dan token. Endpoint sinkronisasi hanya menerima token dengan `role: service`. |
| **Database** | Shared Resource | SQLite (`data/database.sqlite`) | Database bersama untuk persistensi pengguna, perangkat, kelas, nilai, transkrip, refresh token, dan audit log. |

---

## 2. Akun Demo & Perangkat Terdaftar

Semua akun demo menggunakan password default yang sama:
```
Password123!
```
*(Tersimpan dalam bentuk hash `bcrypt` di database, bukan plain text).*

| Username | Nama Lengkap | Role | NIM | Device ID Terdaftar | Keterangan & Hak Akses |
|---|---|---|---|---|---|
| `admin1` | Administrator Sistem | `admin` | `-` | `DEV-ADMIN-01` | Melihat transkrip semua mahasiswa |
| `dosen_budi` | Dr. Budi Hartono, M.Kom. | `dosen` | `-` | `DEV-DOSEN-01` | Pengampu kelas `IF-301` (Keamanan Informasi) |
| `dosen_siti` | Siti Rahma, M.T. | `dosen` | `-` | `DEV-DOSEN-02` | Pengampu kelas `IF-302` (Sistem Terdistribusi) |
| `mhs_ahmad` | Ahmad Pratama | `mahasiswa` | `220101` | `DEV-MHS-01` | Terdaftar di `IF-301` (draft) dan `IF-302` (final) |
| `mhs_bambang` | Bambang Wijaya | `mahasiswa` | `220102` | `DEV-MHS-02` | Terdaftar di `IF-301` (draft) |
| `mhs_citra` | Citra Dewi | `mahasiswa` | `220103` | `DEV-MHS-03` | Terdaftar di `IF-302` (draft) |

---

## 3. Data Awal Kelas & Nilai

1. **Kelas `IF-301` (Keamanan Informasi, 3 SKS)**:
   - Dosen Pengampu: `dosen_budi`
   - Mahasiswa:
     - `mhs_ahmad` (NIM `220101`): Nilai 88.0, Status: `Draft` (Belum final).
     - `mhs_bambang` (NIM `220102`): Nilai 75.0, Status: `Draft` (Belum final).
2. **Kelas `IF-302` (Sistem Terdistribusi, 3 SKS)**:
   - Dosen Pengampu: `dosen_siti`
   - Mahasiswa:
     - `mhs_ahmad` (NIM `220101`): Nilai 92.0, Status: `Final` (Sudah disinkronkan ke Transkrip dengan nilai huruf `A`).
     - `mhs_citra` (NIM `220103`): Nilai 81.0, Status: `Draft` (Belum final).

---

## 4. Struktur Direktori Proyek

```
zero-trust-sistem-nilai/
├── .env                          # Konfigurasi environment lokal (diabaikan git)
├── .env.example                  # Contoh template variabel environment
├── .gitignore                    # File & folder yang diabaikan git
├── package.json                  # Dependensi dan skrip proyek
├── README.md                     # Dokumentasi arsitektur dan panduan
├── IMPLEMENTATION_PLAN.md        # Rencana bertahap implementasi
├── database/
│   ├── schema.sql                # DDL skema database SQLite
│   ├── seed.js                   # Skrip seed data awal (idempotent)
│   └── reset.js                  # Skrip pembersihan dan seeding ulang database
├── shared/
│   ├── config.js                 # Loader konfigurasi berbasis dotenv
│   ├── constants.js              # Definisi konstanta role, status, dan header
│   └── db.js                     # Koneksi SQLite (better-sqlite3)
├── gateway/
│   ├── app.js                    # Express app API Gateway (PEP)
│   └── server.js                 # Entrypoint server Gateway (port 3000)
├── service-nilai/
│   ├── app.js                    # Express app Service Nilai
│   └── server.js                 # Entrypoint server Service Nilai (port 3001)
├── service-transkrip/
│   ├── app.js                    # Express app Service Transkrip
│   └── server.js                 # Entrypoint server Service Transkrip (port 3002)
├── scripts/
│   └── start-all.js              # Runner untuk menjalankan ketiga service sekaligus
└── tests/
    └── foundation.test.js        # Pengujian fondasi, database, & health check
```

---

## 5. Cara Instalasi & Menjalankan Aplikasi

### Prasyarat
- Node.js versi 18 ke atas (Direkomendasikan Node.js LTS).
- NPM versi 9 ke atas.

### 1. Instalasi Dependensi
```bash
npm install
```

### 2. Konfigurasi Environment
Salin template konfigurasi `.env.example` ke `.env`:
```bash
cp .env.example .env
```
*(Konfigurasi default port 3000, 3001, 3002 dan secret demo sudah siap digunakan).*

### 3. Migrasi & Seeding Database
Jalankan skrip seed idempotent (dapat dijalankan berulang kali tanpa membuat duplikasi):
```bash
npm run seed
```
Jika ingin mereset database dari awal:
```bash
npm run reset
```

### 4. Menjalankan Layanan

**Opsi A — Menjalankan ketiga layanan sekaligus:**
```bash
npm start
```

**Opsi B — Menjalankan layanan secara individual di terminal terpisah:**
- Terminal 1 (API Gateway):
  ```bash
  npm run start:gateway
  ```
- Terminal 2 (Service Nilai):
  ```bash
  npm run start:nilai
  ```
- Terminal 3 (Service Transkrip):
  ```bash
  npm run start:transkrip
  ```

### 5. Memeriksa Status Layanan (Health Check)
Uji ketiga endpoint health check:
```bash
# API Gateway (Port 3000)
curl http://localhost:3000/health

# Service Nilai (Port 3001)
curl http://localhost:3001/health

# Service Transkrip (Port 3002)
curl http://localhost:3002/health
```

---

## 6. Pengujian Otomatis

Jalankan test suite menggunakan test runner bawaan Node.js:
```bash
npm test
```

Hasil pengujian mencakup:
- Verifikasi respon HTTP 200 pada endpoint `/health` ketiga aplikasi.
- Verifikasi keberadaan dan integritas 6 user demo dengan verifikasi hash bcrypt password.
- Verifikasi binding perangkat terdaftar untuk masing-masing user.
- Verifikasi keberadaan 2 kelas dan pemisahan dosen pengampu.
- Verifikasi relasi nilai dan transkrip.
- Verifikasi sifat idempotensi skrip seed database.

---

## 7. Status Tahapan & Pekerjaan Keamanan Selanjutnya

- [x] **Tahap 1: Fondasi & Arsitektur Dasar** (Selesai dan terverifikasi).
- [ ] **Tahap 2: Autentikasi & Token Management**:
  - `POST /auth/login` (verifikasi kredensial + device binding header `X-Device-ID`).
  - `POST /auth/refresh` & `POST /auth/logout` (manajemen rotasi refresh token di DB).
  - `POST /auth/service` (penerbitan service token 5 menit untuk Service Nilai).
- [ ] **Tahap 3: Policy Enforcement Point & Policy Engine**:
  - Validasi access token JWT & verifikasi header `X-Device-ID`.
  - Pengecekan kebijakan berbasis atribut di database (ABAC).
  - Pengecekan aturan jam akses (07.00 - 21.00 WIB).
  - Pencatatan keputusan akses ke tabel `audit_logs`.
  - Penyisipan header internal `X-Gateway-Secret`.
- [ ] **Tahap 4: Service Nilai**:
  - Validasi ganda (`X-Gateway-Secret` dan JWT).
  - Filter akses `GET /nilai` dan `PUT /nilai/:id`.
  - Finalisasi `POST /kelas/:id/finalisasi` dan pemanggilan antar-service ke Gateway.
- [ ] **Tahap 5: Service Transkrip**:
  - Filter akses `GET /transkrip/:nim`.
  - Proteksi ketat `POST /transkrip/sinkron` hanya untuk `role: service`.
