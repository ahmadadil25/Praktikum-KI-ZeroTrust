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

## 2. Rencana Tahapan Pengembangan

### Tahap 1: Fondasi, Skema Database, Seed, dan Health Check (Saat Ini)
- [x] Inisialisasi proyek Node.js CommonJS & instalasi dependensi (`express`, `better-sqlite3`, `jsonwebtoken`, `bcryptjs`, `dotenv`, `http-proxy-middleware`, `supertest`).
- [x] Konfigurasi environment `.env.example` dan `.env`.
- [x] Skema database SQLite lengkap:
  - `users`: identitas, peran, password hash, NIM (untuk mahasiswa).
  - `devices`: device ID terdaftar per user, status aktif/blokir.
  - `classes`: data kelas kuliah dan dosen pengampu.
  - `grades`: nilai mahasiswa, status finalisasi (`0` draft, `1` final), timestamp update.
  - `transcripts`: data transkrip hasil sinkronisasi nilai yang telah difinalisasi.
  - `refresh_tokens`: penyimpanan refresh token ter-hash dan status revoke.
  - `audit_logs`: pencatatan lengkap keputusan akses gateway (waktu, subject, endpoint, device, hasil allow/deny, alasan).
- [x] Skrip seed idempotent (`npm run seed`) dengan data uji lengkap:
  - 1 Admin
  - 2 Dosen
  - 3 Mahasiswa
  - 2 Kelas dengan dosen berbeda
  - 1 Device terdaftar untuk masing-masing user
  - Data nilai contoh (draft dan final)
  - Akun demo dengan password ter-hash (`bcryptjs`)
- [x] Modul aplikasi dasar & Health Check endpoint (`/health`) untuk:
  - API Gateway (Port 3000)
  - Service Nilai (Port 3001)
  - Service Transkrip (Port 3002)
- [x] Automated test untuk Health Check & integritas database.

### Tahap 2: Autentikasi, Device Binding & Token Management
- [ ] Endpoint `POST /auth/login`: validasi kredensial pengguna dan header `X-Device-ID` terdaftar; penerbitan JWT Access Token (10 menit) dan Refresh Token (1 hari).
- [ ] Endpoint `POST /auth/refresh`: rotasi refresh token dengan verifikasi hash di database.
- [ ] Endpoint `POST /auth/logout`: pencabutan (revocation) refresh token di database.
- [ ] Endpoint `POST /auth/service`: penerbitan Service Token (5 menit, role `service`) khusus untuk pemanggilan antar-service Service Nilai menggunakan client ID & secret.

### Tahap 3: Policy Engine (PE/PA) & API Gateway (PEP)
- [ ] Implementasi Policy Engine (`gateway/policy.js`):
  - Validasi JWT signature & expiration.
  - Validasi kepemilikan device (`X-Device-ID`).
  - Aturan jam akses (07.00 - 21.00 WIB) untuk operasi mutasi nilai dan finalisasi.
  - Pengecekan atribut database (ownership kelas untuk dosen, NIM untuk mahasiswa).
- [ ] Interceptor API Gateway & Audit Logging:
  - Mencatat setiap hasil allow/deny dan alasan detail ke tabel `audit_logs`.
  - Meneruskan request yang lolos verifikasi dengan menambahkan header rahasia `X-Gateway-Secret`.

### Tahap 4: Service Nilai (Port 3001)
- [ ] Verifikasi ganda: validasi `X-Gateway-Secret` dan verifikasi JWT token.
- [ ] Endpoint `GET /nilai`: mahasiswa melihat nilai miliknya; dosen melihat nilai mahasiswa di kelas yang diampunya.
- [ ] Endpoint `PUT /nilai/:id`: dosen memperbarui nilai mahasiswa pada kelas yang diampu jika belum difinalisasi dan dalam jam operasional.
- [ ] Endpoint `POST /kelas/:id/finalisasi`: dosen memfinalisasi seluruh nilai pada kelasnya, kemudian Service Nilai meminta Service Token ke Gateway dan mengirim permintaan sinkronisasi transkrip ke Service Transkrip melalui Gateway.

### Tahap 5: Service Transkrip (Port 3002)
- [ ] Verifikasi ganda: validasi `X-Gateway-Secret` dan verifikasi JWT token.
- [ ] Endpoint `GET /transkrip/:nim`: mahasiswa hanya melihat transkrip miliknya; admin melihat transkrip mahasiswa mana pun.
- [ ] Endpoint `POST /transkrip/sinkron`: proteksi ketat hanya untuk Service Token (`role: service`); menolak token user apapun; menyalin nilai yang telah difinalisasi ke tabel `transcripts`.

### Tahap 6: Pengujian Integrasi, Keamanan Zero Trust & Dokumentasi
- [ ] Automated integration tests untuk seluruh skenario positif dan skenario pelanggaran keamanan (Negative test cases: invalid token, unregistered device, out-of-hours modification, unauthorized grade change, direct service access without gateway secret, token tampering).
- [ ] Dokumentasi lengkap di `README.md` dan panduan pengujian menggunakan Postman / cURL.
