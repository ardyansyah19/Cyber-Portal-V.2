<?php
/**
 * doc_functions.php
 * -----------------------------------------------------
 * Fitur berbagi dokumen terenkripsi (envelope encryption).
 *
 * Alur:
 *  1. File asli dienkripsi dengan DEK (Data Encryption Key) acak, AES-256-GCM.
 *  2. DEK dibungkus 2x secara independen:
 *     a) pw_wrapped_dek   -> dibuka pakai kunci turunan dari PASSWORD dokumen (PBKDF2)
 *     b) owner_wrapped_dek -> dibuka pakai MASTER KEY server (khusus owner yang sudah login)
 *  3. File asli, DEK asli, dan password TIDAK PERNAH disimpan di database/disk.
 *
 * Jadi kalau database bocor: penyerang masih perlu password dokumen ATAU
 * master key server (yang ada di ENV, terpisah dari DB) untuk buka isi file.
 * -----------------------------------------------------
 */

require_once __DIR__ . '/functions.php';

/* =====================================================
 * Primitif AES-256-GCM
 * ===================================================== */
function aes_encrypt(string $plaintext, string $key): array
{
    $iv  = random_bytes(12); // 96-bit IV standar untuk GCM
    $tag = '';
    $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    if ($ciphertext === false) {
        throw new RuntimeException('Enkripsi gagal.');
    }
    return ['ciphertext' => $ciphertext, 'iv' => $iv, 'tag' => $tag];
}

/**
 * Mengembalikan plaintext, atau false jika kunci salah / data dirusak
 * (auth tag GCM akan otomatis gagal cocok -> ini juga jadi mekanisme
 * verifikasi password tanpa perlu simpan hash password terpisah).
 */
function aes_decrypt(string $ciphertext, string $key, string $iv, string $tag)
{
    return openssl_decrypt($ciphertext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
}

function derive_key_from_password(string $password, string $salt): string
{
    // PBKDF2-SHA256, 100.000 iterasi -> memperlambat brute force offline terhadap password dokumen
    return hash_pbkdf2('sha256', $password, $salt, 100000, 32, true);
}

/* =====================================================
 * VALIDASI FILE UPLOAD
 * ===================================================== */
function validate_uploaded_file(array $file): array
{
    $errors = [];

    if (!isset($file['error']) || $file['error'] !== UPLOAD_ERR_OK) {
        $errors[] = 'Upload gagal (kode error: ' . ($file['error'] ?? 'unknown') . ').';
        return $errors;
    }

    if ($file['size'] > MAX_UPLOAD_SIZE) {
        $errors[] = 'Ukuran file melebihi batas ' . (MAX_UPLOAD_SIZE / 1024 / 1024) . ' MB.';
    }

    $ext = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    if (!array_key_exists($ext, ALLOWED_DOC_TYPES)) {
        $errors[] = 'Ekstensi file tidak diizinkan. Hanya PDF, DOC, DOCX.';
        return $errors;
    }

    // Jangan percaya Content-Type dari browser — cek magic bytes asli via fileinfo
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $realMime = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);

    // Beberapa .docx terdeteksi sebagai application/zip oleh finfo (karena docx = zip container)
    $validMimes = [ALLOWED_DOC_TYPES[$ext]];
    if ($ext === 'docx') {
        $validMimes[] = 'application/zip';
    }

    if (!in_array($realMime, $validMimes, true)) {
        $errors[] = 'Isi file tidak cocok dengan ekstensinya (terdeteksi: ' . htmlspecialchars($realMime) . '). Upload ditolak demi keamanan.';
    }

    return $errors;
}

/* =====================================================
 * UPLOAD + ENKRIPSI DOKUMEN BARU
 * ===================================================== */
function store_encrypted_document(PDO $pdo, int $ownerId, array $file, string $docPassword, ?string $expiresAt = null): string
{
    $plaintext = file_get_contents($file['tmp_name']);
    if ($plaintext === false) {
        throw new RuntimeException('Gagal membaca file yang diupload.');
    }

    $ext  = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
    $mime = ALLOWED_DOC_TYPES[$ext];

    // 1) Enkripsi isi file dengan DEK acak
    $dek = random_bytes(32);
    $fileEnc = aes_encrypt($plaintext, $dek);

    // 2) Bungkus DEK dengan kunci turunan PASSWORD dokumen
    $salt = random_bytes(16);
    $pwKey = derive_key_from_password($docPassword, $salt);
    $pwWrap = aes_encrypt($dek, $pwKey);

    // 3) Bungkus DEK dengan MASTER KEY server (untuk akses owner tanpa password)
    $ownerWrap = aes_encrypt($dek, DOC_MASTER_KEY);

    // 4) Simpan ciphertext file ke disk dengan nama acak (bukan nama asli)
    if (!is_dir(STORAGE_DIR)) {
        mkdir(STORAGE_DIR, 0700, true);
    }
    $storedFilename = bin2hex(random_bytes(24)) . '.enc';
    file_put_contents(STORAGE_DIR . '/' . $storedFilename, $fileEnc['ciphertext']);
    chmod(STORAGE_DIR . '/' . $storedFilename, 0600);

    // 5) Hapus segera semua salinan plaintext & DEK dari memori (sedapat mungkin)
    sodium_memzero($plaintext);
    sodium_memzero($dek);
    sodium_memzero($pwKey);

    // 6) Simpan metadata ke database (TIDAK ADA plaintext/DEK di sini)
    $shareToken = bin2hex(random_bytes(32)); // token 256-bit, anti-tebak

    $stmt = $pdo->prepare(
        'INSERT INTO documents (
            share_token, owner_id, original_filename, stored_filename, mime_type, file_size,
            file_iv, file_tag,
            password_salt, pw_wrap_iv, pw_wrap_tag, pw_wrapped_dek,
            owner_wrap_iv, owner_wrap_tag, owner_wrapped_dek,
            expires_at
        ) VALUES (
            :token, :owner, :orig, :stored, :mime, :size,
            :fiv, :ftag,
            :salt, :pwiv, :pwtag, :pwdek,
            :oiv, :otag, :odek,
            :expires
        )'
    );
    $stmt->execute([
        ':token'   => $shareToken,
        ':owner'   => $ownerId,
        ':orig'    => $file['name'],
        ':stored'  => $storedFilename,
        ':mime'    => $mime,
        ':size'    => $file['size'],
        ':fiv'     => base64_encode($fileEnc['iv']),
        ':ftag'    => base64_encode($fileEnc['tag']),
        ':salt'    => base64_encode($salt),
        ':pwiv'    => base64_encode($pwWrap['iv']),
        ':pwtag'   => base64_encode($pwWrap['tag']),
        ':pwdek'   => base64_encode($pwWrap['ciphertext']),
        ':oiv'     => base64_encode($ownerWrap['iv']),
        ':otag'    => base64_encode($ownerWrap['tag']),
        ':odek'    => base64_encode($ownerWrap['ciphertext']),
        ':expires' => $expiresAt,
    ]);

    log_activity($pdo, $ownerId, 'DOCUMENT_UPLOAD');

    return $shareToken;
}

/* =====================================================
 * RATE LIMITING KHUSUS DOKUMEN (per dokumen + per IP)
 * ===================================================== */
function is_document_locked(array $doc): bool
{
    return !empty($doc['locked_until']) && strtotime($doc['locked_until']) > time();
}

function record_document_attempt(PDO $pdo, int $documentId, bool $success): void
{
    $stmt = $pdo->prepare(
        'INSERT INTO document_access_log (document_id, ip_address, success) VALUES (:id, :ip, :ok)'
    );
    $stmt->execute([':id' => $documentId, ':ip' => get_client_ip(), ':ok' => $success ? 1 : 0]);
}

function register_document_failed_attempt(PDO $pdo, array $doc): void
{
    $attempts = (int) $doc['failed_attempts'] + 1;
    $lockUntil = null;

    if ($attempts >= DOC_MAX_ATTEMPTS) {
        $lockUntil = date('Y-m-d H:i:s', strtotime('+' . DOC_LOCKOUT_MIN . ' minutes'));
        $attempts = 0;
    }

    $stmt = $pdo->prepare('UPDATE documents SET failed_attempts = :a, locked_until = :l WHERE id = :id');
    $stmt->execute([':a' => $attempts, ':l' => $lockUntil, ':id' => $doc['id']]);
}

function reset_document_failed_attempts(PDO $pdo, int $documentId): void
{
    $stmt = $pdo->prepare('UPDATE documents SET failed_attempts = 0, locked_until = NULL WHERE id = :id');
    $stmt->execute([':id' => $documentId]);
}

function is_document_ip_rate_limited(PDO $pdo, int $documentId): bool
{
    $stmt = $pdo->prepare(
        'SELECT COUNT(*) AS total FROM document_access_log
         WHERE document_id = :doc AND ip_address = :ip AND success = 0
           AND attempted_at > (NOW() - INTERVAL 10 MINUTE)'
    );
    $stmt->execute([':doc' => $documentId, ':ip' => get_client_ip()]);
    return ((int) $stmt->fetch()['total']) >= 20;
}

/* =====================================================
 * BUKA DOKUMEN VIA PASSWORD (untuk penerima/publik)
 * Mengembalikan plaintext file, atau null jika password salah.
 * ===================================================== */
function open_document_with_password(array $doc, string $password): ?string
{
    $salt  = base64_decode($doc['password_salt']);
    $pwKey = derive_key_from_password($password, $salt);

    $dek = aes_decrypt(
        base64_decode($doc['pw_wrapped_dek']),
        $pwKey,
        base64_decode($doc['pw_wrap_iv']),
        base64_decode($doc['pw_wrap_tag'])
    );

    if ($dek === false) {
        return null; // password salah -> auth tag GCM tidak cocok
    }

    $ciphertext = file_get_contents(STORAGE_DIR . '/' . $doc['stored_filename']);
    $plaintext = aes_decrypt(
        $ciphertext,
        $dek,
        base64_decode($doc['file_iv']),
        base64_decode($doc['file_tag'])
    );

    sodium_memzero($dek);

    return $plaintext === false ? null : $plaintext;
}

/* =====================================================
 * BUKA DOKUMEN SEBAGAI OWNER (tanpa password, via master key)
 * ===================================================== */
function open_document_as_owner(array $doc): ?string
{
    $dek = aes_decrypt(
        base64_decode($doc['owner_wrapped_dek']),
        DOC_MASTER_KEY,
        base64_decode($doc['owner_wrap_iv']),
        base64_decode($doc['owner_wrap_tag'])
    );

    if ($dek === false) {
        return null;
    }

    $ciphertext = file_get_contents(STORAGE_DIR . '/' . $doc['stored_filename']);
    $plaintext = aes_decrypt(
        $ciphertext,
        $dek,
        base64_decode($doc['file_iv']),
        base64_decode($doc['file_tag'])
    );

    sodium_memzero($dek);

    return $plaintext === false ? null : $plaintext;
}

function increment_download_count(PDO $pdo, int $documentId): void
{
    $stmt = $pdo->prepare('UPDATE documents SET download_count = download_count + 1 WHERE id = :id');
    $stmt->execute([':id' => $documentId]);
}
