# Sistem Login (PHP + MySQL)
By Ahmad Riko Dyansyah

Sistem login demo dengan berbagai lapisan keamanan (defense-in-depth).
Ditujukan untuk pembelajaran/pengembangan lokal — sesuaikan lagi sebelum dipakai produksi.

## 🆕 Fitur Berbagi Dokumen Terenkripsi

Setiap dokumen (PDF/DOC/DOCX) dienkripsi dengan **AES-256-GCM** dan dilindungi password unik yang ditentukan pengirim. Tanpa password itu, dokumen tidak bisa dibuka oleh siapa pun.

### Cara kerja (envelope encryption)

1. File asli dienkripsi dengan **DEK** (Data Encryption Key) acak sekali pakai per dokumen.
2. DEK itu sendiri dibungkus **dua kali secara independen**:
   - 🔑 **Amplop password**: dibuka dengan kunci turunan PBKDF2 dari password yang ditentukan pengirim → dipakai oleh siapa pun yang tahu password (link `share.php?token=...`).
   - 🔑 **Amplop owner**: dibuka dengan *master key* rahasia di server (`DOC_MASTER_KEY`, disimpan di ENV) → dipakai otomatis saat pengirim (owner) login dan mengunduh dari `my_documents.php`, tanpa perlu masukkan password lagi.
3. File plaintext, DEK asli, dan password **tidak pernah** disimpan di database maupun disk.
4. Auth tag GCM otomatis menjadi mekanisme verifikasi password — password salah akan gagal decrypt, tanpa perlu simpan hash password terpisah.

Konsekuensinya: kalau database bocor sendirian, isi file tetap tidak bisa dibuka — penyerang butuh salah satu dari dua "kunci" independen (password dokumen ATAU master key server) yang keduanya tidak disimpan bersamaan dengan ciphertext.

### Lapisan keamanan tambahan pada fitur ini

| Ancaman                        | Mitigasi |
|--------------------------------|----------|
| Tebak-tebak link dokumen       | `share_token` acak 256-bit (`random_bytes(32)`), bukan ID berurutan |
| Brute force password dokumen   | Rate limiting per-IP per-dokumen + lockout otomatis setelah 5x gagal |
| Upload file berbahaya (webshell menyamar .pdf) | Validasi ekstensi + cek *magic bytes* asli via `finfo`, bukan hanya `Content-Type` dari browser |
| Akses langsung ke file di server | Ciphertext disimpan dengan nama acak, folder `storage/` diblokir total via `.htaccess` (`Require all denied`) |
| Kebocoran isi file lewat cache/log | Header `Cache-Control: no-store`, file plaintext hanya ada di memori saat proses download, langsung di-*zero* (`sodium_memzero`) setelah dikirim |
| Kedaluwarsa akses               | Opsional: dokumen bisa diset kedaluwarsa otomatis (1/7/30 hari) |

### Setup tambahan untuk fitur dokumen

```bash
mysql -u root -p secure_login_db < database_documents.sql

# Generate master key 256-bit, simpan sebagai ENV (JANGAN taruh di kode/git)
php -r "echo base64_encode(random_bytes(32));"
export DOC_MASTER_KEY="hasil_base64_di_atas"
```

Alur pemakaian:
1. Login → **Bagikan Dokumen Terenkripsi** (`upload_document.php`) → upload file + tentukan password dokumen.
2. Salin link yang muncul, kirim ke penerima **lewat jalur berbeda** dari password (mis. link via email, password via WhatsApp) — praktik standar untuk berbagi rahasia (out-of-band).
3. Penerima buka link (`share.php?token=...`), masukkan password → file otomatis terdekripsi & terunduh.
4. Owner bisa lihat semua dokumennya, unduh tanpa password, atau hapus permanen di `my_documents.php`.

## Cara Menjalankan

1. **Buat database & tabel**
   ```bash
   mysql -u root -p < database.sql
   ```

2. **Set environment variable** (jangan hardcode kredensial):
   ```bash
   export DB_HOST=127.0.0.1
   export DB_NAME=secure_login_db
   export DB_USER=db_user
   export DB_PASS="password_kuat_anda"
   export APP_PEPPER="string_rahasia_panjang_dan_acak_ganti_ini"
   ```

3. **Isi data dummy dengan hash yang valid**:
   ```bash
   php seed.php
   ```
   Ini akan menampilkan 3 akun dummy beserta passwordnya:
   - `admin_demo` / `P@ssw0rdKuat!123`
   - `budi_santoso` / `Budi#Aman2026`
   - `siti_rahayu` / `Siti$Secure99`

4. **Jalankan server PHP** (untuk testing lokal):
   ```bash
   php -S localhost:8000
   ```
   Buka `http://localhost:8000/login.php`

## Struktur File

```
secure-login/
├── database.sql            # skema tabel: users, login_attempts, activity_log
├── database_documents.sql  # skema tabel tambahan: documents, document_access_log
├── seed.php                # generate password hash valid untuk dummy user
├── config.php               # koneksi DB + hardening session + security headers + master key
├── functions.php            # CSRF, rate limiting, hashing, validasi, audit log
├── doc_functions.php        # enkripsi/dekripsi dokumen (envelope encryption AES-256-GCM)
├── login.php                # form + proses login (+ honeypot anti-bot, auto rehash)
├── register.php             # form + proses registrasi
├── dashboard.php             # halaman terproteksi (butuh login)
├── upload_document.php       # upload & enkripsi dokumen baru + set password
├── my_documents.php          # daftar dokumen milik owner (unduh/hapus)
├── download_owner.php        # unduh sebagai owner tanpa password (via master key)
├── share.php                  # halaman publik: masukkan password untuk buka dokumen
├── logout.php                # hancurkan session dengan aman
├── storage/                   # (dibuat otomatis) file terenkripsi, diblokir via .htaccess
└── .htaccess                  # blokir akses langsung ke file sensitif
