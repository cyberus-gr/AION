/**
 * vault.js — Client-side file encryption / decryption using Web Crypto API.
 *
 * Algorithm: AES-256-GCM with a key derived via PBKDF2-SHA256 (310,000 iterations).
 * A random 16-byte salt and 12-byte IV are generated per encryption operation.
 * The entire encrypted blob is packaged as a JSON .vault file so it is self-describing
 * and can be decrypted without any server or app-specific state.
 *
 * Vault file format (JSON):
 *   {
 *     "magic":    "PASSVAULT/1",
 *     "filename": "original_name.pdf",
 *     "type":     "application/pdf",
 *     "size":     12345,
 *     "date":     "2026-03-21T10:00:00Z",
 *     "salt":     "<base64 16 bytes>",
 *     "iv":       "<base64 12 bytes>",
 *     "data":     "<base64 encrypted bytes>"
 *   }
 *
 * Security note: the IV and salt are random and single-use. The same key + passphrase
 * combination will produce a different vault file every time (IND-CPA secure).
 * AES-GCM also provides authenticated encryption: wrong passphrase = decryption error.
 */

'use strict';

const VAULT_MAGIC = 'PASSVAULT/1';
const PBKDF2_ITER = 310_000;

/* ── Internal helpers ────────────────────────────────────────── */

function b64encode(buf) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function b64decode(str) {
  return Uint8Array.from(atob(str), c => c.charCodeAt(0));
}

async function deriveKey(passphrase, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/* ── Public API ──────────────────────────────────────────────── */

/**
 * Encrypt a File object with the given passphrase.
 * Returns a Blob of the .vault JSON package, ready to download.
 */
async function encryptFile(file, passphrase) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const key  = await deriveKey(passphrase, salt);

  const plaintext  = await file.arrayBuffer();
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plaintext);

  const pkg = JSON.stringify({
    magic:    VAULT_MAGIC,
    filename: file.name,
    type:     file.type || 'application/octet-stream',
    size:     file.size,
    date:     new Date().toISOString(),
    salt:     b64encode(salt),
    iv:       b64encode(iv),
    data:     b64encode(ciphertext),
  });

  return new Blob([pkg], { type: 'application/json' });
}

/**
 * Decrypt a .vault Blob with the given passphrase.
 * Returns { filename, type, blob } on success.
 * Throws a descriptive Error on bad passphrase or corrupted file.
 */
async function decryptVault(vaultBlob, passphrase) {
  let pkg;
  try {
    const text = await vaultBlob.text();
    pkg = JSON.parse(text);
  } catch {
    throw new Error('Invalid vault file — could not parse JSON.');
  }

  if (pkg.magic !== VAULT_MAGIC) {
    throw new Error('Unrecognised file format. Only PASSVAULT/1 files are supported.');
  }

  const salt = b64decode(pkg.salt);
  const iv   = b64decode(pkg.iv);
  const data = b64decode(pkg.data);

  let key;
  try {
    key = await deriveKey(passphrase, salt);
  } catch {
    throw new Error('Key derivation failed. The passphrase may be empty.');
  }

  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
  } catch {
    // AES-GCM authentication failure = wrong key or corrupted file
    throw new Error('Decryption failed — wrong passphrase or corrupted file.');
  }

  return {
    filename: pkg.filename ?? 'decrypted_file',
    type:     pkg.type    ?? 'application/octet-stream',
    blob:     new Blob([plaintext], { type: pkg.type }),
  };
}

/**
 * Trigger a browser download of a Blob.
 */
function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a   = document.createElement('a');
  a.href     = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
}

/**
 * Format bytes to human-readable string.
 */
function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(1)} GB`;
}
