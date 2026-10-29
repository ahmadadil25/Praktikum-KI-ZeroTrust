# Rencana Implementasi: Zero Trust Sistem Nilai
**Mata Kuliah**: Keamanan Informasi (KP70065004)  
**Topik**: Zero Trust Security Architecture (NIST SP 800-207)  
**Proyek**: `zero-trust-sistem-nilai`

---

## 1. Ringkasan Arsitektur & Prinsip Zero Trust
Sistem ini mengimplementasikan prinsip-prinsip inti Zero Trust:
1. **Never Trust, Always Verify**: Setiap permintaan wajib diautentikasi dan diotorisasi di Policy Enforcement Point (API Gateway), serta diverifikasi ulang di internal resource service (Service Nilai dan Service Transkrip) dengan verifikasi token dan `X-Gateway-Secret`.
2. **Least Privilege**: Akses dibatasi berdasarkan peran (Mahasiswa, Dosen, Admin, Service) dan kepemilikan data aktual di database (bukan sekadar claim di token).
3. **Assume Breach**: Layanan internal tidak dapat diakses langsung oleh publik. Jika salah satu komponen dikompromikan, token berdurasi singkat (10 menit untuk user, 5 menit untuk service), device binding terdaftar, dan audit logging lengkap membatasi eskalasi ancaman.

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

---

## 2. Status Tahapan Pengembangan

### Tahap 1: Fondasi, Skema Database, Seed, dan Health Check
- [x] Inisialisasi proyek Node.js CommonJS & dependensi (`express`, `better-sqlite3`, `jsonwebtoken`, `bcryptjs`, `dotenv`, `http-proxy-middleware`, `supertest`).
- [x] Konfigurasi environment `.env.example` dan `.env`.
- [x] Skema database SQLite lengkap (7 tabel):
  - `users`: identitas, peran, password hash bcrypt, NIM (untuk mahasiswa).
  - `devices`: device ID terdaftar per user, status aktif/blokir.
  - `classes`: data kelas kuliah dan dosen pengampu.
  - `grades`: nilai mahasiswa, status finalisasi (`0` draft, `1` final), timestamp update.
  - `transcripts`: data transkrip hasil sinkronisasi nilai yang telah difinalisasi.
  - `refresh_tokens`: penyimpanan refresh token ter-hash dan status revoke.
  - `audit_logs`: pencatatan lengkap keputusan akses gateway (waktu, subject, endpoint, device, hasil allow/deny, alasan).
- [x] Skrip seed idempotent (`npm run seed`) dengan data uji lengkap:
  - 1 Admin (`admin1`)
  - 2 Dosen (`dosen_budi`, `dosen_siti`)
  - 3 Mahasiswa (`mhs_ahmad`, `mhs_bambang`, `mhs_citra`)
  - 2 Kelas dengan dosen berbeda (`IF-301`, `IF-302`)
  - 1 Device terdaftar untuk masing-masing user (`DEV-*`)
  - Data nilai contoh (draft dan final)
  - Akun demo dengan password ter-hash bcrypt (`Password123!`)
- [x] Modul aplikasi dasar & Health Check endpoint (`/health`) untuk:
  - API Gateway (Port 3000)
  - Service Nilai (Port 3001)
  - Service Transkrip (Port 3002)

### Tahap 2: Autentikasi, Device Binding & Token Management
- [x] Endpoint `POST /auth/login`: validasi kredensial pengguna dan header `X-Device-ID` terdaftar; penerbitan JWT Access Token (10 menit) dan Refresh Token (1 hari).
- [x] Endpoint `POST /auth/refresh`: rotasi refresh token dengan verifikasi hash di database, validasi kedaluwarsa, revoke status, dan validasi device.
- [x] Endpoint `POST /auth/logout`: pencabutan (revocation) refresh token di database.
- [x] Endpoint `POST /auth/service`: penerbitan Service Token (5 menit, role `service`) khusus untuk pemanggilan antar-service Service Nilai menggunakan client ID & secret.

### Tahap 3: Policy Engine (PE/PA) & API Gateway (PEP)
- [x] Implementasi Policy Engine (`gateway/policy.js`):
  - Validasi JWT signature & expiration.
  - Validasi kepemilikan device (`X-Device-ID`).
  - Aturan jam akses operasional (07.00 - 21.00 Asia/Jakarta) untuk operasi mutasi nilai dan finalisasi.
  - Pengecekan atribut database (ABAC: kepemilikan kelas untuk dosen, kepemilikan NIM untuk mahasiswa, status final nilai).
- [x] Interceptor API Gateway (PEP Middleware) & Audit Logging:
  - Mencatat setiap hasil allow/deny dan alasan detail ke tabel `audit_logs`.
  - Meneruskan request yang lolos verifikasi dengan menambahkan header rahasia `X-Gateway-Secret`.

### Tahap 4: Service Nilai (Port 3001)
- [x] Verifikasi ganda: validasi `X-Gateway-Secret` dan verifikasi JWT token.
- [x] Endpoint `GET /nilai`: mahasiswa melihat nilai miliknya; dosen melihat nilai mahasiswa di kelas yang diampunya.
- [x] Endpoint `PUT /nilai/:id`: dosen memperbarui nilai mahasiswa pada kelas yang diampu jika belum difinalisasi dan dalam jam operasional.
- [x] Endpoint `POST /kelas/:id/finalisasi`: dosen memfinalisasi seluruh nilai pada kelasnya, kemudian Service Nilai meminta Service Token ke Gateway dan mengirim permintaan sinkronisasi transkrip ke Service Transkrip melalui Gateway.

### Tahap 5: Service Transkrip (Port 3002)
- [x] Verifikasi ganda: validasi `X-Gateway-Secret` dan verifikasi JWT token.
- [x] Endpoint `GET /transkrip/:nim`: mahasiswa hanya melihat transkrip miliknya; admin melihat transkrip mahasiswa mana pun.
- [x] Endpoint `POST /transkrip/sinkron`: proteksi ketat hanya untuk Service Token (`role: service`); menolak token user apapun; menyalin nilai yang telah difinalisasi ke tabel `transcripts`.

### Tahap 6: Pengujian Integrasi, Keamanan Zero Trust & Dokumentasi
- [x] Automated integration tests (44 pengujian) yang mencakup:
  - Login valid & invalid (salah password, user tidak ditemukan, missing header).
  - Penolakan device tidak terdaftar atau diblokir.
  - Penolakan token kedaluwarsa.
  - Penolakan akses mahasiswa ke data transkrip mahasiswa lain.
  - Penolakan dosen mengakses atau mengubah kelas yang bukan diampunya.
  - Penolakan perubahan nilai di luar jam akses operasional (07.00 - 21.00 WIB) & konfirmasi data tidak berubah.
  - Penolakan akses langsung ke resource service tanpa `X-Gateway-Secret` atau tanpa token valid.
  - Penolakan token user (mahasiswa, dosen, admin) untuk endpoint sinkronisasi transkrip.
  - Alur lengkap end-to-end (login -> edit nilai -> finalisasi -> sinkronisasi via token service -> cek transkrip).
- [x] Dokumentasi lengkap di `README.md` dengan panduan testing cURL / Postman.
