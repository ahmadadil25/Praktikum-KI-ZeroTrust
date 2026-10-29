# Zero Trust Sistem Nilai Akademik
> Implementasi Arsitektur Keamanan Zero Trust (NIST SP 800-207) pada Sistem Pengelolaan Nilai Akademik.  
> Tugas Praktikum Individu Keamanan Informasi (KP70065004) · Informatika Universitas Siliwangi.

---

## 1. Arsitektur Sistem & Prinsip Zero Trust

Sistem ini menerapkan prinsip-prinsip inti Zero Trust Architecture sesuai standar **NIST SP 800-207**:
1. **Never Trust, Always Verify**: Tidak ada zona internal yang dipercaya secara implisit. Setiap request diperiksa di **Policy Enforcement Point (API Gateway Port 3000)** terhadap kebijakan kontekstual (identitas, peran, device binding, jam operasional). Di tingkat resource service (Service Nilai Port 3001 dan Service Transkrip Port 3002), diterapkan **Defense in Depth**: service memverifikasi ulang header rahasia `X-Gateway-Secret` DAN tanda tangan serta masa berlaku token JWT.
2. **Least Privilege**: Pembatasan hak akses berbasis peran (RBAC) dan atribut database aktual (ABAC):
   - Mahasiswa hanya dapat melihat nilai dan transkrip miliknya sendiri.
   - Dosen hanya dapat melihat dan mengubah nilai pada kelas yang diampunya, serta hanya untuk nilai yang belum difinalisasi.
   - Admin hanya dapat melihat transkrip seluruh mahasiswa.
   - Endpoint sinkronisasi transkrip hanya dapat diakses menggunakan Service Token sah dari Service Nilai.
3. **Assume Breach**: Durasi token dibuat singkat (Access Token: 10 menit, Service Token: 5 menit). Refresh token disimpan ter-hash (SHA-256) di database dan mendukung pencabutan instan (revocation via logout). Akses langsung ke service internal tanpa melalui Gateway ditolak. Gateway juga membersihkan header buatan client (anti-spoofing).

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
| **API Gateway** | Policy Enforcement Point (PEP) | `3000` | Pintu masuk tunggal client. Meminta otorisasi ke Policy Engine, mencatat audit log, menyisipkan `X-Gateway-Secret`, dan meneruskan request yang sah. |
| **Policy Engine / PA** | Policy Engine / Policy Admin | Terintegrasi di Gateway | Mengelola login, verifikasi device terdaftar, evaluasi aturan ABAC dari database, dan jam akses operasional. |
| **Service Nilai** | Resource Service | `3001` | Mengelola data nilai dan kelas mahasiswa. Memverifikasi `X-Gateway-Secret` dan token. Mengirim request sinkronisasi ke Service Transkrip via Gateway saat finalisasi nilai. |
| **Service Transkrip** | Resource Service | `3002` | Mengelola transkrip akademik mahasiswa. Memverifikasi `X-Gateway-Secret` dan token. Endpoint sinkronisasi hanya menerima token dengan `role: service`. |
| **Database** | Shared Resource | SQLite (`data/database.sqlite`) | Database bersama untuk persistensi pengguna, perangkat, kelas, nilai, transkrip, refresh token, dan audit log. |

---

## 2. Tabel Kebijakan Akses (Policy Decision)

| Endpoint | Method | Ditangani oleh | Role yang Diizinkan | Kondisi Akses & Aturan Zero Trust |
|---|---|---|---|---|
| `/auth/login` | `POST` | Gateway | Semua user | Kredensial valid dan `X-Device-ID` terdaftar & aktif di DB |
| `/auth/refresh` | `POST` | Gateway | Semua user | Refresh token valid, belum dicabut, dan device terdaftar |
| `/auth/logout` | `POST` | Gateway | Semua user | Refresh token dicabut (revoked) di database |
| `/auth/service` | `POST` | Gateway | Service Nilai | Client ID dan Client Secret khusus Service Nilai valid |
| `/nilai` | `GET` | Service Nilai | Mahasiswa, Dosen | Mahasiswa: hanya nilai miliknya. Dosen: hanya kelas yang diampunya |
| `/nilai/:id` | `GET` | Service Nilai | Mahasiswa, Dosen | Mahasiswa: hanya detail nilai miliknya. Dosen: hanya kelas yang diampunya |
| `/nilai/:id` | `PUT` | Service Nilai | Dosen | Kelas yang diampu, nilai belum final, dan dalam jam akses (07.00–21.00 WIB) |
| `/kelas/:id/finalisasi` | `POST` | Service Nilai | Dosen | Kelas yang diampu dan dalam jam akses (07.00–21.00 WIB). Memanggil sinkronisasi via Gateway |
| `/transkrip/:nim` | `GET` | Service Transkrip | Mahasiswa, Admin | Mahasiswa: hanya NIM miliknya. Admin: semua NIM |
| `/transkrip/sinkron` | `POST` | Service Transkrip | Service Nilai | **Hanya menerima Service Token (`role: service`)**. Token pengguna mana pun ditolak |

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

## 4. Konfigurasi Environment (`.env`)

Konfigurasi disimpan pada file `.env` di root direktori (template di `.env.example`):

| Variabel | Default | Deskripsi |
|---|---|---|
| `PORT_GATEWAY` | `3000` | Port listening API Gateway (PEP) |
| `PORT_NILAI` | `3001` | Port listening Service Nilai |
| `PORT_TRANSKRIP` | `3002` | Port listening Service Transkrip |
| `SERVICE_NILAI_URL` | `http://localhost:3001` | URL target proxy gateway untuk Service Nilai |
| `SERVICE_TRANSKRIP_URL` | `http://localhost:3002` | URL target proxy gateway untuk Service Transkrip |
| `GATEWAY_URL` | `http://localhost:3000` | URL Gateway yang dipanggil oleh Service Nilai |
| `JWT_ACCESS_SECRET` | `zt-access-secret-...` | Kunci simetris penandatanganan Access Token |
| `JWT_ACCESS_EXPIRES_IN` | `10m` | Durasi masa berlaku Access Token (10 menit) |
| `JWT_REFRESH_SECRET` | `zt-refresh-secret-...` | Kunci simetris penandatanganan Refresh Token |
| `JWT_REFRESH_EXPIRES_IN` | `1d` | Durasi masa berlaku Refresh Token (1 hari) |
| `JWT_SERVICE_SECRET` | `zt-service-secret-...`| Kunci penandatanganan Service Token (5 menit) |
| `JWT_SERVICE_EXPIRES_IN` | `5m` | Durasi masa berlaku Service Token (5 menit) |
| `GATEWAY_SECRET` | `zt-gateway-internal-...`| Secret rahasia yang disisipkan Gateway PEP ke service |
| `SERVICE_CLIENT_ID` | `service-nilai-client` | Client ID Service Nilai untuk meminta Service Token |
| `SERVICE_CLIENT_SECRET` | `service-nilai-internal-...`| Client Secret Service Nilai |
| `DB_PATH` | `./data/database.sqlite` | Lokasi file database SQLite bersama |
| `ACCESS_HOURS_START` | `7` | Jam mulai operasional perubahan nilai (07.00 WIB) |
| `ACCESS_HOURS_END` | `21` | Jam selesai operasional perubahan nilai (21.00 WIB) |
| `ACCESS_TIMEZONE` | `Asia/Jakarta` | Zona waktu operasional (WIB) |

---

## 5. Cara Instalasi & Menjalankan Aplikasi

### 1. Instalasi Dependensi
```bash
npm install
```

### 2. Inisialisasi Database
Jalankan skrip seed idempotent:
```bash
npm run seed
```
*(Atau jalankan `npm run reset` jika ingin membersihkan seluruh tabel dan seed ulang).*

### 3. Menjalankan Ketiga Layanan Sekaligus
```bash
npm start
```
*Layanan berjalan pada: Gateway (`http://localhost:3000`), Service Nilai (`http://localhost:3001`), Service Transkrip (`http://localhost:3002`).*

---

## 6. Panduan Pengujian API Manual (cURL / Postman)

### 1. Login Pengguna
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: DEV-DOSEN-01" \
  -d '{"username": "dosen_budi", "password": "Password123!"}'
```
*Respon: `access_token` (10 menit) dan `refresh_token` (1 hari).*

### 2. Mengambil Daftar Nilai (Mahasiswa / Dosen)
```bash
# Sebagai Dosen Budi (melihat nilai mahasiswa di kelas IF-301)
curl -X GET http://localhost:3000/nilai \
  -H "Authorization: Bearer <TOKEN_DOSEN_BUDI>" \
  -H "X-Device-ID: DEV-DOSEN-01"

# Sebagai Mahasiswa Ahmad (melihat nilai miliknya sendiri)
curl -X GET http://localhost:3000/nilai \
  -H "Authorization: Bearer <TOKEN_MHS_AHMAD>" \
  -H "X-Device-ID: DEV-MHS-01"
```

### 3. Memperbarui Nilai Mahasiswa (Hanya Dosen Pengampu & Jam Operasional)
```bash
curl -X PUT http://localhost:3000/nilai/1 \
  -H "Authorization: Bearer <TOKEN_DOSEN_BUDI>" \
  -H "X-Device-ID: DEV-DOSEN-01" \
  -H "Content-Type: application/json" \
  -d '{"nilai": 92.5}'
```

### 4. Finalisasi Nilai Kelas (Memicu Sinkronisasi Transkrip Otomatis)
```bash
curl -X POST http://localhost:3000/kelas/1/finalisasi \
  -H "Authorization: Bearer <TOKEN_DOSEN_BUDI>" \
  -H "X-Device-ID: DEV-DOSEN-01"
```

### 5. Memeriksa Transkrip Mahasiswa
```bash
# Mahasiswa melihat transkrip miliknya sendiri
curl -X GET http://localhost:3000/transkrip/220101 \
  -H "Authorization: Bearer <TOKEN_MHS_AHMAD>" \
  -H "X-Device-ID: DEV-MHS-01"

# Admin melihat transkrip mahasiswa mana pun
curl -X GET http://localhost:3000/transkrip/220101 \
  -H "Authorization: Bearer <TOKEN_ADMIN>" \
  -H "X-Device-ID: DEV-ADMIN-01"
```

### 6. Refresh Token
```bash
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -H "X-Device-ID: DEV-DOSEN-01" \
  -d '{"refresh_token": "<REFRESH_TOKEN>"}'
```

### 7. Logout (Pencabutan Token)
```bash
curl -X POST http://localhost:3000/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "<REFRESH_TOKEN>"}'
```

---

## 7. Pengujian Otomatis & Skenario Zero Trust

Jalankan seluruh rangkaian uji coba (52 test case pada 18 test suite):
```bash
npm test
```

### Cakupan 14 Skenario Pengujian Wajib:
1. **Mahasiswa hanya melihat nilai miliknya**: Terverifikasi pada `GET /nilai` dan `GET /nilai/:id`.
2. **Mahasiswa ditolak ketika mengakses nilai atau transkrip mahasiswa lain**: Terverifikasi dengan HTTP 403 Forbidden.
3. **Dosen hanya dapat mengubah nilai kelas yang diampunya**: Percobaan Dosen Budi mengubah nilai kelas Dosen Siti ditolak dengan HTTP 403 Forbidden.
4. **Dosen ditolak ketika mengubah nilai final**: Nilai berstatus `status_final = 1` tidak dapat diubah (HTTP 403 / 400).
5. **Perubahan dan finalisasi ditolak di luar jam akses**: Percobaan mutasi di luar 07.00–21.00 Asia/Jakarta ditolak (HTTP 403).
6. **Finalisasi memicu sinkronisasi transkrip melalui gateway**: Service Nilai memperoleh token service dari Gateway dan menyinkronkan data nilai final ke Service Transkrip.
7. **Sinkronisasi ditolak ketika memakai token user**: Token mahasiswa, dosen, maupun admin ditolak pada `POST /transkrip/sinkron` (HTTP 403).
8. **Sinkronisasi ditolak ketika token service kedaluwarsa atau tidak valid**: Token dengan tanda tangan palsu atau kedaluwarsa ditolak (HTTP 401).
9. **Request langsung ke service tanpa gateway secret ditolak**: Panggilan bypass langsung ke port 3001 atau 3002 ditolak dengan HTTP 403 Direct Access Forbidden.
10. **Request dengan gateway secret tetapi tanpa token valid ditolak**: Secret saja tidak cukup untuk meloloskan request (HTTP 401 Unauthorized).
11. **Admin dapat melihat transkrip mahasiswa lain, tetapi tidak dapat sinkronisasi**: Admin diizinkan `GET /transkrip/:nim`, namun ditolak pada `POST /transkrip/sinkron`.
12. **Setiap keputusan akses tercatat di audit log**: Keputusan `ALLOW` dan `DENY` tersimpan di tabel `audit_logs` tanpa membocorkan rahasia atau raw token.
13. **Pengulangan sinkronisasi tidak membuat duplikasi data**: Transaksi upsert idempoten menjamin data transkrip konsisten tanpa duplikasi.
14. **Kegagalan sinkronisasi ditangani dengan benar**: Jika downstream transkrip mengalami kegagalan, Service Nilai mengembalikan HTTP 502 dan tidak memberikan respons sukses palsu.
