# Sistem Login (PHP + MySQL)
By Ahmad Riko Dyansyah

Sistem login demo dengan berbagai lapisan keamanan (defense-in-depth).
Ditujukan untuk pembelajaran/pengembangan lokal — sesuaikan lagi sebelum dipakai produksi.

## Fitur Keamanan

| Ancaman              | Mitigasi yang diterapkan |
|----------------------|---------------------------|
| SQL Injection        | PDO **prepared statements** di semua query, `PDO::ATTR_EMULATE_PREPARES => false` |
| Password bocor       | `password_hash()` (Argon2id/bcrypt) + **pepper** tambahan via `hash_hmac` sebelum hashing |
| Brute force          | Rate limiting per-IP + penguncian akun otomatis setelah `MAX_LOGIN_ATTEMPTS` gagal |
| Timing attack        | `hash_equals()` untuk cek CSRF token, `password_verify()` dummy saat user tidak ditemukan |
| User enumeration     | Pesan error login digeneralisasi ("username atau password salah") |
| CSRF                 | Token acak per-session, wajib dicocokkan di setiap form POST |
| Session hijacking    | Cookie `HttpOnly`, `Secure` (saat HTTPS), `SameSite=Strict`, regenerasi session ID berkala |
| Session fixation     | `session_regenerate_id(true)` setiap kali login berhasil |
| XSS                  | `htmlspecialchars()` di semua output, Content-Security-Policy header |
| Clickjacking         | Header `X-Frame-Options: DENY` |
| Idle session         | Auto logout setelah 30 menit tidak aktif |
| Audit trail          | Tabel `activity_log` mencatat login/logout/registrasi |

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
```

## Catatan Sebelum Produksi

- Ganti `APP_PEPPER` dengan string acak panjang (≥32 karakter) dan simpan di secrets manager, bukan di repo.
- Aktifkan HTTPS dan uncomment baris pemaksaan HTTPS di `.htaccess`.
- Pertimbangkan menambahkan **2FA (TOTP)** — kolom `two_factor_secret` sudah disediakan di skema.
- Pertimbangkan CAPTCHA (misal Cloudflare Turnstile) setelah beberapa kali gagal login.
- Pastikan ekstensi `pdo_mysql` terpasang di server (`sudo apt install php-mysql` di Ubuntu/Debian).
- Batasi hak akses user MySQL (`db_user`) hanya ke database ini, jangan pakai akun root.
- ✅ Sudah diterapkan: auto-rehash password (`password_needs_rehash`) & honeypot anti-bot di form login.
- **`DOC_MASTER_KEY` adalah kunci paling sensitif di seluruh sistem** — simpan di secrets manager (mis. AWS Secrets Manager/Vault), rotasi berkala, dan JANGAN pernah commit ke Git.
- Pastikan modul PHP `sodium` dan `openssl` aktif di server (`php -m | grep -E "sodium|openssl"`).
- Pertimbangkan batasi `max_downloads` per dokumen dan kirim notifikasi email ke owner tiap kali dokumen diunduh.
- Untuk kebutuhan compliance lebih tinggi, tambahkan penghapusan otomatis (cron) untuk dokumen yang sudah `expires_at` terlewati.
