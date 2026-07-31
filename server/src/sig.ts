// Ed25519 signature verification via Node's WebCrypto implementation, using
// raw (32-byte) public keys so the format matches exactly what the browser's
// crypto.subtle.exportKey('raw', ...) produces on the client - no ASN.1/SPKI
// wrapping needed on either side.
import { webcrypto } from 'node:crypto';

const keyCache = new Map<string, webcrypto.CryptoKey>();

async function importRawEd25519PublicKey(edPubB64: string): Promise<webcrypto.CryptoKey> {
  const cached = keyCache.get(edPubB64);
  if (cached) return cached;

  const raw = Buffer.from(edPubB64, 'base64');
  const key = await webcrypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
  keyCache.set(edPubB64, key);
  return key;
}

/**
 * Verifies an Ed25519 signature. `data` is the exact canonical byte string
 * the client signed (see messages.ts for the format). Returns false (never
 * throws) on any malformed input so callers can reject uniformly.
 */
export async function verifyEd25519(
  edPubB64: string,
  data: string,
  sigB64: string,
): Promise<boolean> {
  try {
    const key = await importRawEd25519PublicKey(edPubB64);
    const sig = Buffer.from(sigB64, 'base64');
    const bytes = new TextEncoder().encode(data);
    return await webcrypto.subtle.verify({ name: 'Ed25519' }, key, sig, bytes);
  } catch {
    return false;
  }
}
