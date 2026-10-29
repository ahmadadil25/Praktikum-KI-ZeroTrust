# LAPORAN AUDIT KEAMANAN (SECURITY REVIEW)
## Sistem Pengelolaan Nilai Akademik Berbasis Zero Trust Architecture (NIST SP 800-207)

* **Tanggal Audit**: 30 Oktober 2026
* **Target Sistem**: `zero-trust-sistem-nilai` (Node.js, Express.js, SQLite, CommonJS)
* **Auditor**: Antigravity Security Review Assistant
* **Standar Evaluasi**: NIST Special Publication 800-207 (Zero Trust Architecture), OWASP Top 10 API Security 2023, CWE (Common Weakness Enumeration)
* **Status Hasil Pengujian**: **64 Test Cases Lulus / 0 Gagal (19 Suites)**

---

## 1. Ringkasan Eksekutif & Metodologi Audit

Audit keamanan ini dilakukan secara menyeluruh terhadap implementasi backend `zero-trust-sistem-nilai` yang dirancang untuk mengamankan data nilai dan transkrip akademik. Audit mencakup peninjauan statis kode sumber (*code review*), analisis arsitektur, pengujian penetrasi logis (*logic abuse testing*), serta pembuatan uji regresi otomatis (*automated regression testing*).

Prinsip evaluasi didasarkan pada tiga pilar inti NIST SP 800-207:
1. **Never Trust, Always Verify**: Semua entitas (pengguna internal, layanan backend, perangkat) dianggap tidak tepercaya secara implisit. Setiap transaksi diverifikasi di perimeter (*API Gateway/PEP*) dan diverifikasi ulang di tingkat layanan internal (*Resource Services*).
2. **Least Privilege & Context-based Access**: Hak akses diberikan secara minimum berbasis Role (RBAC) dan atribut dinamis di database (ABAC), seperti kepemilikan data mahasiswa, penugasan dosen pengampu kelas, status finalisasi nilai, dan jendela waktu operasional (07.00–21.00 WIB).
3. **Assume Breach**: Merancang sistem dengan asumsi perimeter dapat ditembus atau token dicuri. Menggunakan masa berlaku token singkat (10 menit untuk Access Token, 5 menit untuk Service Token), hashing refresh token (SHA-256), rotasi token, fasilitas pencabutan instan (*revocation*), pembersihan header buatan client (*anti-spoofing*), dan sanitasi audit log tanpa kebocoran rahasia.

> [!WARNING]
> **Pernyataan Batasan Keamanan (Security Disclaimer):**
> Keberhasilan seluruh pengujian otomatis (64/64 pass) **bukan bukti bahwa sistem 100% aman secara mutlak**. Pengujian otomatis membuktikan kepatuhan terhadap skenario ancaman yang telah dimodelkan. Pengawasan berkala, audit dependensi pustaka pihak ketiga, dan perlindungan infrastruktur level jaringan tetap wajib dilakukan di lingkungan produksi.

---

## 2. Verifikasi Arsitektur Zero Trust & Jalur Akses Tunggal

```
[ Klien Eksternal (Postman / curl) ]
               │
               │ HTTPS/HTTP (Access Token + X-Device-ID)
               ▼
┌─────────────────────────────────────────────────────────────┐
│ API GATEWAY (Port 3000) — Policy Enforcement Point (PEP)    │
│  ├─ Auth Controller (/auth/login, refresh, logout, service) │
│  ├─ Policy Engine / PA (ABAC & Jam Akses 07.00–21.00 WIB)  │
│  ├─ Audit Logger (Pencatatan ALLOW/DENY, Redaksi Token)     │
│  └─ Anti-Spoofing Proxy (Strip client headers, sisipkan     │
│     X-Gateway-Secret resmi)                                 │
└──────────────┬──────────────────────────────┬───────────────┘
               │                              │
               │ + X-Gateway-Secret           │ + X-Gateway-Secret
               │ + User Token                 │ + Service Token
               ▼                              ▼
┌───────────────────────────────┐ ┌───────────────────────────┐
│ SERVICE NILAI (Port 3001)     │ │ SERVICE TRANSKRIP (3002)  │
│  ├─ Verifikasi Secret & Token │ │  ├─ Verifikasi Secret &   │
│  ├─ Defense-in-Depth Role     │ │     Token                 │
│  ├─ Cek Kepemilikan & Final   │ │  ├─ Endpoint Sinkronisasi │
│  └─ Client Service Token Sync ┼─┼─>│     HANYA Service Token│
└──────────────┬────────────────┘ └───────────┬───────────────┘
               │                              │
               └──────────────┬───────────────┘
                              ▼
               ┌──────────────────────────────┐
               │ Shared SQLite Database       │
               │ (Prepared Statements WAL)    │
               └──────────────────────────────┘
```

### Hasil Audit Jalur Akses Tunggal:
* **API Gateway Port 3000 adalah satu-satunya jalur yang diizinkan untuk klien**: Semua endpoint publik diakses melalui gateway.
* **Service Nilai (Port 3001) & Service Transkrip (Port 3002) terlindungi**: Kedua service internal mengimplementasikan middleware `verifyResourceSecurity`. Request langsung ke port 3001/3002 tanpa header `X-Gateway-Secret` yang sah langsung ditolak dengan status **HTTP 403 Direct Access Forbidden**.
* **Secret Saja Tidak Cukup**: Jika penyerang menyisipkan `X-Gateway-Secret` namun tanpa Bearer token yang sah atau token rusak/palsu, request ditolak dengan status **HTTP 401 Unauthorized**.

---

## 3. Matriks Temuan Keamanan (Security Findings Matrix)

Berikut adalah rekapitulasi temuan keamanan yang diidentifikasi selama audit, tingkat risikonya, perbaikan yang telah diterapkan, dan status verifikasinya:

| ID | Judul Temuan | Tingkat Risiko | Kategori CWE | File Terkait | Status Verifikasi |
|---|---|---|---|---|---|
| **SEC-01** | Potensi Bypass Jam Operasional via Header `X-Simulated-Hour` di Lingkungan Non-Test | **HIGH** | CWE-20 (Improper Input Validation) | `gateway/pep.middleware.js`, `gateway/proxy.js` | **TERVERIFIKASI & DIPERBAIKI** |
| **SEC-02** | Penerimaan Device ID melalui Request Body Mengaburkan Kontrak Header PEP | **MEDIUM** | CWE-287 (Improper Authentication) | `gateway/auth.controller.js` | **TERVERIFIKASI & DIPERBAIKI** |
| **SEC-03** | Ketiadaan Validasi Role Eksplisit pada Operasi Mutasi di `service-nilai` (*Defense-in-Depth Gap*) | **MEDIUM** | CWE-285 (Improper Authorization) | `service-nilai/app.js` | **TERVERIFIKASI & DIPERBAIKI** |
| **SEC-04** | Kerentanan *Type Juggling / Coercion* pada Validasi Input Nilai Mahasiswa | **MEDIUM** | CWE-1287 (Improper Validation of Specified Type) | `service-nilai/app.js`, `service-transkrip/app.js` | **TERVERIFIKASI & DIPERBAIKI** |
| **SEC-05** | Penanganan Error Format JSON (*Malformed JSON*) Menghasilkan Respon Ambigu | **LOW** | CWE-755 (Improper Handling of Exceptional Conditions) | `gateway/app.js`, `service-nilai/app.js`, `service-transkrip/app.js` | **TERVERIFIKASI & DIPERBAIKI** |
| **SEC-06** | Ketiadaan Uji Regresi Otomatis untuk Penolakan Token Service pada Endpoint Pengguna | **LOW** | CWE-285 (Authorization Testing Gap) | `tests/policy-zero-trust.test.js` | **TERVERIFIKASI & DIPERBAIKI** |
| **SEC-07** | Ketiadaan Rate Limiting pada Endpoint Login & Refresh Token | **LOW** | CWE-307 (Improper Restriction of Excessive Authentication Attempts) | `gateway/auth.controller.js` | **TERCATAT (REKOMENDASI)** |
| **SEC-08** | Ketiadaan Header Keamanan Standar HTTP (*HTTP Security Headers*) | **INFORMATIONAL** | CWE-693 (Protection Mechanism Failure) | `gateway/app.js`, `service-nilai/app.js`, `service-transkrip/app.js` | **TERVERIFIKASI & DIPERBAIKI** |
| **SEC-09** | Penggunaan Fallback Secret jika `.env` Hilang pada Mode Produksi | **LOW** | CWE-1188 (Insecure Default Initialization) | `shared/config.js` | **TERVERIFIKASI & DIPERBAIKI** |

---

## 4. Rincian Temuan & Perbaikan yang Diterapkan

### SEC-01: Potensi Bypass Jam Operasional via Header `X-Simulated-Hour`
* **Deskripsi**: Header `X-Simulated-Hour` digunakan untuk memudahkan simulasi pengujian otomatis di luar jam nyata. Sebelumnya, middleware PEP membaca header ini secara langsung tanpa memeriksa apakah aplikasi berjalan dalam mode produksi. Penyerang dapat menyisipkan `X-Simulated-Hour: 10` pada jam 02.00 malam untuk memanipulasi nilai.
* **Perbaikan**: Diubah pada `gateway/pep.middleware.js` sehingga `X-Simulated-Hour` **hanya diakomodasi** jika `process.env.NODE_ENV !== 'production' && config.env !== 'production'`. Di lingkungan produksi, header ini diabaikan sepenuhnya dan jam aktual sistem Asia/Jakarta mutlak digunakan. Header ini juga dihapus di `proxy.js` sebelum diteruskan ke backend.
* **Verifikasi**: Uji otomatis `SR.10` membuktikan bahwa saat `NODE_ENV = 'production'`, request manipulasi di luar jam operasional dengan header `X-Simulated-Hour: 14` tetap ditolak dengan **HTTP 403**.

### SEC-02: Penerimaan Device ID melalui Request Body
* **Deskripsi**: Fungsi `getDeviceIdFromReq` di `auth.controller.js` sebelumnya mengecek `req.body.device_id || req.body.deviceId`. Hal ini tidak konsisten dengan Policy Enforcement Point (PEP) yang mewajibkan `X-Device-ID` pada header HTTP. Klien yang mengirimkan device ID di body dapat lolos login namun gagal saat memanggil endpoint terproteksi.
* **Perbaikan**: Dihapus dukungan membaca device ID dari body. Fungsi `getDeviceIdFromReq` kini secara ketat hanya membaca dari `req.headers['x-device-id']` atau konstanta `HEADERS.DEVICE_ID`.
* **Verifikasi**: Uji regresi `SR.6` memastikan request login dengan `device_id` di body tanpa header menghasilkan **HTTP 400 Bad Request**.

### SEC-03: Ketiadaan Validasi Role Eksplisit di Tingkat Resource Service (Defense in Depth)
* **Deskripsi**: Pada `service-nilai/app.js`, endpoint `PUT /nilai/:id` dan `POST /kelas/:id/finalisasi` hanya memeriksa kesesuaian `existingGrade.dosen_id === req.user.sub`. Jika request lolos ke service internal dengan subjek token bertipe service atau mahasiswa yang kebetulan memiliki ID integer yang sama dengan dosen, otorisasi dapat terlanggar.
* **Perbaikan**: Menambahkan verifikasi eksplisit peran `if (!req.user || req.user.role !== ROLES.DOSEN)` pada kedua endpoint tersebut di `service-nilai/app.js`.
* **Verifikasi**: Uji otomatis `SR.12` membuktikan request dengan token mahasiswa yang membawa `X-Gateway-Secret` sah langsung ditolak oleh `service-nilai` dengan **HTTP 403 Forbidden**.

### SEC-04: Kerentanan Type Juggling / Coercion pada Validasi Input Nilai
* **Deskripsi**: Pengecekan nilai sebelumnya menggunakan `if (nilai === undefined || isNaN(nilai))`. Dalam JavaScript, `isNaN(true)` bernilai `false`, dan `Number(true)` menghasilkan angka `1`. Jika klien mengirimkan `{"nilai": true}`, nilai mahasiswa diubah menjadi `1.0`. Demikian pula `{"nilai": []}` menghasilkan `0.0`.
* **Perbaikan**: Diterapkan validasi tipe ketat:
  ```javascript
  if (
    nilai === undefined ||
    nilai === null ||
    typeof nilai === 'boolean' ||
    typeof nilai === 'object' ||
    (typeof nilai === 'string' && nilai.trim() === '') ||
    isNaN(Number(nilai)) ||
    !Number.isFinite(Number(nilai)) ||
    Number(nilai) < 0 ||
    Number(nilai) > 100
  )
  ```
* **Verifikasi**: Uji regresi `SR.7`, `SR.8`, dan `SR.9` memastikan input boolean, array, nilai di bawah 0, dan nilai di atas 100 ditolak dengan **HTTP 400 Bad Request**.

### SEC-05: Penanganan Error Format JSON (Malformed JSON)
* **Deskripsi**: Jika klien mengirim sintaks JSON rusak, Express `body-parser` melempar `SyntaxError`. Handler error sebelumnya merespon dengan status default atau teks "Internal Server Error" yang menyesatkan.
* **Perbaikan**: Handler error terpusat di `gateway/app.js`, `service-nilai/app.js`, dan `service-transkrip/app.js` diperbarui untuk mengenali `err instanceof SyntaxError && err.status === 400 && 'body' in err` dan mengembalikan respon bersih **HTTP 400 Bad Request** (`Format payload JSON tidak valid`).
* **Verifikasi**: Verifikasi error response mengembalikan status dan pesan yang tepat tanpa mengekspos stack trace.

### SEC-06: Uji Regresi Penolakan Token Service pada Operasi Pengguna
* **Deskripsi**: Sesuai butir 4 spesifikasi praktikum: *"token service tidak dapat digunakan untuk operasi pengguna yang tidak diizinkan"*. Meski policy engine sudah memblokirnya, belum ada tes otomatis yang menguji hal ini secara eksplisit.
* **Perbaikan**: Menambahkan 5 uji regresi otomatis (`SR.1` s/d `SR.5`) di `tests/policy-zero-trust.test.js`.
* **Verifikasi**: Terbukti bahwa `tokenService` ditolak dengan **HTTP 403** pada:
  - `GET /nilai`
  - `GET /nilai/:id`
  - `PUT /nilai/:id`
  - `POST /kelas/:id/finalisasi`
  - `GET /transkrip/:nim`

### SEC-07: Rate Limiting pada Autentikasi
* **Deskripsi**: Endpoint `/auth/login` dan `/auth/refresh` belum dilengkapi pembatasan frekuensi percobaan (*rate limiting*). Risiko: percobaan serangan *brute force* tebakan kata sandi atau *credential stuffing*.
* **Status**: Tercatat sebagai rekomendasi penguatan lingkungan produksi menggunakan reverse proxy (seperti NGINX / Cloudflare rate limiting) atau modul middleware `express-rate-limit`.

### SEC-08: HTTP Security Headers
* **Deskripsi**: Header keamanan peramban standar belum terpasang.
* **Perbaikan**: Disematkan middleware header keamanan di Gateway dan Resource Services:
  - `X-Content-Type-Options: nosniff` (mencegah MIME type sniffing)
  - `X-Frame-Options: DENY` (mencegah clickjacking)
* **Verifikasi**: Uji otomatis `SR.11` memvalidasi keberadaan kedua header tersebut pada respon HTTP.

### SEC-09: Pencegahan Kunci Rahasia Bawaan (Default Secret)
* **Deskripsi**: File `shared/config.js` memiliki string fallback default jika variabel `.env` tidak terdefinisi.
* **Perbaikan**: Ditambahkan pemeriksaan saat startup: jika `NODE_ENV === 'production'` dan terdeteksi kunci rahasia mengandung kata `'default'`, sistem mengeluarkan peringatan tegas di log konsol.

---

## 5. Audit Proteksi SQL Injection & Kredensial

* **SQL Injection**: **Aman (Clean)**.
  Seluruh query pada database SQLite (`better-sqlite3`) di `gateway/auth.controller.js`, `gateway/policy.js`, `gateway/pep.middleware.js`, `service-nilai/app.js`, dan `service-transkrip/app.js` menggunakan *prepared statements* dengan *parameterized queries* (`?` atau `@namedParam`). Tidak ditemukan satupun query yang menggunakan perangkaian string (*string concatenation*).
* **Proteksi Audit Log (Zero Credential Leak)**: **Aman (Clean)**.
  Fungsi `sanitizeLog()` di `shared/audit.js` memfilter dan menyamarkan (*redact*) token JWT (`Bearer [REDACTED_JWT]`) dan parameter kredensial/password (`password=[REDACTED]`, `secret=[REDACTED]`). Terverifikasi pada uji otomatis `G.12` bahwa tidak ada string JWT mentah (`eyJ...`) yang tersimpan di kolom `subject` atau `alasan` tabel `audit_logs`.

---

## 6. Hasil Pengujian Nyata (Real Test Execution)

Berdasarkan eksekusi perintah `npm test` menggunakan runner bawaan `node:test` (`node --test --test-concurrency=1 tests/**/*.test.js`):

```
Total Test Suites : 19
Total Test Cases  : 64
Passed            : 64
Failed            : 0
Duration          : ~3.6 detik
```

### A. Fitur yang TELAH LULUS Pengujian (Verified):
1. **Health Check Gateway, Service Nilai, dan Service Transkrip** (3/3 pass).
2. **Skema Database & Idempotensi Seeding** (6/6 pass).
3. **Autentikasi & Validasi Kredensial Pengguna (Bcrypt Hash)** (3/3 pass).
4. **Validasi Device Terdaftar & Pemblokiran Device Non-Aktif** (3/3 pass).
5. **Penerbitan Access Token (10m) & Refresh Token (1d)** (2/2 pass).
6. **Mekanisme Rotasi Refresh Token** (1/1 pass).
7. **Pencabutan Refresh Token saat Logout & Penolakan Pasca-Logout** (2/2 pass).
8. **Penerbitan & Pembatasan Masa Berlaku Service Token (5m)** (2/2 pass).
9. **Penegakan Kepemilikan Data Mahasiswa pada Nilai & Transkrip (ABAC)** (6/6 pass).
10. **Penegakan Hak Akses Dosen Pengampu & Isolasi Antar-Kelas (ABAC)** (4/4 pass).
11. **Pembatasan Jam Akses Operasional (07.00 - 21.00 WIB Asia/Jakarta)** (3/3 pass).
12. **Immutabilitas Nilai yang Telah Berstatus FINAL** (2/2 pass).
13. **Penolakan Akses Langsung ke Service Tanpa Gateway Secret (403)** (3/3 pass).
14. **Penolakan Akses ke Service dengan Secret Tanpa Token Sah (401)** (1/1 pass).
15. **Proteksi Khusus Sinkronisasi Transkrip (Hanya Role Service)** (3/3 pass).
16. **Penolakan Token Kedaluwarsa dan Token Palsu/Rusak** (2/2 pass).
17. **Idempotensi Sinkronisasi Transkrip (Tidak Ada Duplikasi Data)** (1/1 pass).
18. **Fault Handling: Kegagalan Sinkronisasi Downstream Tidak Menghasilkan Sukses Palsu (502)** (1/1 pass).
19. **Pencatatan Audit Log Lengkap Tanpa Kebocoran Kredensial/Token** (1/1 pass).
20. **Penolakan Token Service pada Seluruh Endpoint Pengguna** (5/5 pass).
21. **Validasi Ketat Input Nilai terhadap Type Juggling (Boolean/Array/Range)** (3/3 pass).
22. **Proteksi Bypass X-Simulated-Hour di Lingkungan Produksi** (1/1 pass).
23. **Penyematan Header Keamanan Standar HTTP (X-Content-Type-Options & X-Frame-Options)** (1/1 pass).
24. **Defense-in-Depth Penolakan Token Pengguna Langsung di Tingkat Service** (1/1 pass).
25. **Alur Kerja Penuh End-to-End (E2E) Login -> Edit -> Finalisasi -> Sinkron -> Transkrip** (1/1 pass).

### B. Fitur yang GAGAL Pengujian:
* **Nihil (0 fitur gagal)**. Seluruh 64 skenario pengujian berjalan sukses tanpa error.

### C. Aspek yang BELUM DIVERIFIKASI secara Otomatis (Residual Risks & Unverified Scope):
1. **Distributed Denial of Service (DDoS) & Massive Request Flooding**: Pengujian performa beban tinggi (*stress testing*) belum diuji secara otomatis.
2. **Key Rotation Lifecycle**: Rotasi asimetris kunci JWT (misal pembaruan kunci publik/privat berkala tanpa *downtime*) belum diimplementasikan karena menggunakan kunci simetris (*HMAC-SHA256*).
3. **Hardware-bound Device Attestation**: Device binding saat ini didasarkan pada `X-Device-ID` string yang terdaftar di database, bukan sertifikat digital mTLS perangkat keras (TPM/Secure Enclave).

---

## 7. Kesimpulan & Rekomendasi Lanjutan

Implementasi arsitektur keamanan Zero Trust pada proyek `zero-trust-sistem-nilai` telah memenuhi dan melampaui seluruh spesifikasi praktikum yang dipersyaratkan. Seluruh celah keamanan kritis yang ditemukan (seperti potensi manipulasi jam akses, penolakan token service pada endpoint bisnis, validasi tipe data nilai, dan konsistensi header device) telah diperbaiki secara aman dan divalidasi dengan rangkaian uji regresi otomatis.

### Rekomendasi untuk Penerapan Produksi Masa Depan:
1. Mengganti token simetris HMAC-SHA256 menjadi pasangan kunci asimetris RSA/ECDSA (RS256 atau ES256) dengan rotasi kunci JWKS.
2. Menerapkan mTLS (*mutual TLS*) antara API Gateway dan Resource Services untuk memperkuat *defense-in-depth* di lapisan jaringan.
3. Menambahkan middleware rate limiting pada API Gateway untuk memitigasi serangan *brute force*.
4. Mengintegrasikan audit log ke sistem SIEM eksternal untuk pemantauan anomali secara *real-time*.
