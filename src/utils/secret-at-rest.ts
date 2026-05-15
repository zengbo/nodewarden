// At-rest protection for 2FA material.
//
// Two storage formats coexist in the `users` table for backward compatibility:
//
//   totp_secret:
//     - new writes:  "enc1:" base64(iv) ":" base64(ciphertext)   (AES-GCM, key from JWT_SECRET via HKDF)
//     - legacy reads: bare base32 secret (still accepted; auto-upgrade on next write)
//
//   totp_recovery_code:
//     - new writes:  "rcv1:" base64(iv) ":" base64(ciphertext)   (AES-GCM, same key family as TOTP, different HKDF info)
//     - legacy reads: bare formatted plaintext code (still accepted)
//
// A leak of the D1 database alone no longer hands an attacker the 2FA shared
// secrets or the recovery codes, provided JWT_SECRET stays out of the dump.

const TOTP_ENVELOPE_PREFIX = 'enc1:';
const RECOVERY_ENVELOPE_PREFIX = 'rcv1:';
const TOTP_HKDF_SALT = 'nodewarden.totp-at-rest.v1';
const TOTP_HKDF_INFO = 'totp-secret';
const RECOVERY_HKDF_INFO = 'totp-recovery-code';
const AES_GCM = 'AES-GCM';
const AES_GCM_IV_BYTES = 12;

function bytesToBase64(bytes: Uint8Array): string {
  let text = '';
  for (let i = 0; i < bytes.length; i++) text += String.fromCharCode(bytes[i]);
  return btoa(text);
}

function base64ToBytes(value: string): Uint8Array {
  const binary = atob(value);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

async function deriveKey(jwtSecret: string, info: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const ikm = await crypto.subtle.importKey('raw', enc.encode(jwtSecret), 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode(TOTP_HKDF_SALT), info: enc.encode(info) },
    ikm,
    256
  );
  return crypto.subtle.importKey('raw', bits, { name: AES_GCM }, false, ['encrypt', 'decrypt']);
}

async function deriveTotpKey(jwtSecret: string): Promise<CryptoKey> {
  return deriveKey(jwtSecret, TOTP_HKDF_INFO);
}

async function deriveRecoveryKey(jwtSecret: string): Promise<CryptoKey> {
  return deriveKey(jwtSecret, RECOVERY_HKDF_INFO);
}

export function isEncryptedTotpSecret(value: string | null | undefined): boolean {
  return typeof value === 'string' && value.startsWith(TOTP_ENVELOPE_PREFIX);
}

export async function encryptTotpSecret(plain: string, jwtSecret: string): Promise<string> {
  const key = await deriveTotpKey(jwtSecret);
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: AES_GCM, iv }, key, new TextEncoder().encode(plain))
  );
  return `${TOTP_ENVELOPE_PREFIX}${bytesToBase64(iv)}:${bytesToBase64(ct)}`;
}

// Returns the plaintext base32 TOTP secret for use with verifyTotpToken.
// Accepts both legacy plaintext and the new envelope; legacy values are
// returned unchanged so existing 2FA enrolments keep working.
export async function readTotpSecret(stored: string | null | undefined, jwtSecret: string): Promise<string | null> {
  if (!stored) return null;
  if (!isEncryptedTotpSecret(stored)) return stored; // legacy plaintext
  const parts = stored.slice(TOTP_ENVELOPE_PREFIX.length).split(':');
  if (parts.length !== 2) return null;
  try {
    const key = await deriveTotpKey(jwtSecret);
    const iv = base64ToBytes(parts[0]);
    const ct = base64ToBytes(parts[1]);
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: AES_GCM, iv }, key, ct));
    return new TextDecoder().decode(pt);
  } catch {
    return null;
  }
}

function normalizeRecoveryCode(raw: string): string {
  return String(raw || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
}

export function isEncryptedRecoveryCode(value: string | null | undefined): boolean {
  return typeof value === 'string' && value.startsWith(RECOVERY_ENVELOPE_PREFIX);
}

export async function encryptRecoveryCode(plain: string, jwtSecret: string): Promise<string> {
  const key = await deriveRecoveryKey(jwtSecret);
  const iv = crypto.getRandomValues(new Uint8Array(AES_GCM_IV_BYTES));
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: AES_GCM, iv }, key, new TextEncoder().encode(plain))
  );
  return `${RECOVERY_ENVELOPE_PREFIX}${bytesToBase64(iv)}:${bytesToBase64(ct)}`;
}

export async function readRecoveryCode(
  stored: string | null | undefined,
  jwtSecret: string
): Promise<string | null> {
  if (!stored) return null;
  if (!isEncryptedRecoveryCode(stored)) return stored; // legacy plaintext
  const parts = stored.slice(RECOVERY_ENVELOPE_PREFIX.length).split(':');
  if (parts.length !== 2) return null;
  try {
    const key = await deriveRecoveryKey(jwtSecret);
    const iv = base64ToBytes(parts[0]);
    const ct = base64ToBytes(parts[1]);
    const pt = new Uint8Array(await crypto.subtle.decrypt({ name: AES_GCM, iv }, key, ct));
    return new TextDecoder().decode(pt);
  } catch {
    return null;
  }
}

function constantTimeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// Verify a recovery code against the stored form. Handles both the legacy
// plaintext format and the new AES-GCM envelope.
export async function verifyRecoveryCodeAgainstStored(
  input: string,
  stored: string | null | undefined,
  jwtSecret: string
): Promise<boolean> {
  if (!stored) return false;
  const normalizedInput = normalizeRecoveryCode(input);
  if (!normalizedInput) return false;

  const plain = await readRecoveryCode(stored, jwtSecret);
  if (!plain) return false;
  const a = new TextEncoder().encode(normalizedInput);
  const b = new TextEncoder().encode(normalizeRecoveryCode(plain));
  return constantTimeEqualBytes(a, b);
}
