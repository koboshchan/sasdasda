// Ed25519 identity: generated in the browser, private key never leaves this
// device (except through the explicit "export identity" backup flow, which
// the user triggers themselves to move to another device - it is never
// sent over the network). Every outgoing message is signed with it; the
// server verifies against the public key registered at signup and rejects
// anything unsigned or invalid (see server/src/messages.ts).
import { bytesToB64, b64ToBytes } from './b64.js';
import { sha256HexBytes } from './hash.js';

const encoder = new TextEncoder();

export interface Identity {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

export async function generateIdentity(): Promise<Identity> {
  const pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, true, [
    'sign',
    'verify',
  ])) as CryptoKeyPair;
  return { publicKey: pair.publicKey, privateKey: pair.privateKey };
}

/** Raw 32-byte public key, base64 - this is exactly what gets registered and what the server imports to verify. */
export async function exportPublicKeyRaw(publicKey: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey('raw', publicKey);
  return bytesToB64(raw);
}

/** sha256 hex of the raw public key bytes - shown to users so they can compare identities out-of-band. */
export async function fingerprint(publicKey: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey('raw', publicKey);
  return sha256HexBytes(raw);
}

/** Same fingerprint, computed from a base64 raw public key (e.g. one fetched over REST) rather than a CryptoKey. */
export async function fingerprintFromRawB64(rawB64: string): Promise<string> {
  return sha256HexBytes(b64ToBytes(rawB64));
}

/**
 * Full backup of an identity as a portable JSON blob (JWK), for the
 * "export identity" flow so a user can move to a new device/browser. This
 * blob contains the private key - treat it like a password.
 */
export async function exportIdentityBackup(identity: Identity): Promise<string> {
  const jwk = await crypto.subtle.exportKey('jwk', identity.privateKey);
  return JSON.stringify(jwk);
}

export async function importIdentityBackup(backupJson: string): Promise<Identity> {
  const jwk = JSON.parse(backupJson) as JsonWebKey;
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'Ed25519' },
    true,
    ['sign'],
  );
  // The private-key JWK also carries the public component ('x'); strip 'd'
  // and reuse it to reconstruct the matching public key.
  const { d: _d, key_ops: _ops, ...pub } = jwk as JsonWebKey & { d?: string };
  const publicKey = await crypto.subtle.importKey(
    'jwk',
    { ...pub, key_ops: ['verify'] },
    { name: 'Ed25519' },
    true,
    ['verify'],
  );
  return { publicKey, privateKey };
}

/** Signs the canonical message string (must match server's canonicalMessage()) and returns base64. */
export async function signMessage(privateKey: CryptoKey, canonical: string): Promise<string> {
  const sig = await crypto.subtle.sign({ name: 'Ed25519' }, privateKey, encoder.encode(canonical));
  return bytesToB64(sig);
}

/** Verifies a signature against a raw base64 public key (e.g. a peer's registered key). */
export async function verifyMessage(
  peerPublicKeyRawB64: string,
  canonical: string,
  sigB64: string,
): Promise<boolean> {
  try {
    const key = await crypto.subtle.importKey(
      'raw',
      b64ToBytes(peerPublicKeyRawB64) as BufferSource,
      { name: 'Ed25519' },
      false,
      ['verify'],
    );
    return await crypto.subtle.verify({ name: 'Ed25519' }, key, b64ToBytes(sigB64) as BufferSource, encoder.encode(canonical));
  } catch {
    return false;
  }
}
