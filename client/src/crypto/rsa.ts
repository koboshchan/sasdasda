// RSA-OAEP(SHA-256) transport encryption using the server's public key,
// fetched once from GET /api/pubkey and cached. Used only to wrap small
// hex-string hashes (a room id H2, or a password hash PH) so the server can
// receive them without them ever crossing the wire in the clear.
import { bytesToB64, b64ToBytes } from './b64.js';

const encoder = new TextEncoder();

export interface ServerPubKey {
  key: CryptoKey;
  fingerprint: string;
}

let cached: ServerPubKey | null = null;

export async function getServerPublicKey(): Promise<ServerPubKey> {
  if (cached) return cached;

  const res = await fetch('/api/pubkey');
  if (!res.ok) throw new Error('Failed to fetch server public key');
  const { spkiB64, fingerprint } = (await res.json()) as { spkiB64: string; fingerprint: string };

  const key = await crypto.subtle.importKey(
    'spki',
    b64ToBytes(spkiB64) as BufferSource,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['encrypt'],
  );

  cached = { key, fingerprint };
  return cached;
}

/** RSA-OAEP encrypts a utf8 string (e.g. a hex hash) under the server's public key. Returns base64. */
export async function rsaEncryptString(plaintext: string): Promise<string> {
  const { key } = await getServerPublicKey();
  const ciphertext = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, key, encoder.encode(plaintext));
  return bytesToB64(ciphertext);
}
