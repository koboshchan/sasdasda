// Ed25519 identity, derived deterministically from the account password so
// it's reproducible on any device with nothing to export or import.
//
// seed = sha256("sc-ed25519-v1|" + password) is the Ed25519 secret key
// (noble's Ed25519 secret key *is* the seed - no separate generation step).
// This is deliberately NOT derived from PH = sha256(password), which the
// server stores (see server/src/auth.ts) to verify logins: seeding from PH
// would mean a compromised server could derive every user's private
// signing key straight out of its own database and forge messages. Seeding
// from the raw password - which never leaves this device - keeps the same
// derive-from-password ergonomics without that exposure. The domain
// separation prefix just keeps this seed distinct from PH even though both
// are sha256 of the same password.
//
// The private key only ever exists as this derived seed. It's never sent
// over the network; the one place it's persisted locally is a base64 copy
// per-account (see store/vault.ts::setIdentitySeed) so a resumed session
// doesn't need the password re-entered, and that copy is deleted on logout
// (see main.ts::handleLogout). Every outgoing message is signed with it;
// the server verifies against the public key registered at signup and
// rejects anything unsigned or invalid (see server/src/messages.ts).
import { ed25519 } from '@noble/curves/ed25519.js';
import { bytesToB64, b64ToBytes } from './b64.js';
import { sha256Hex, sha256HexBytes, hexToBytes } from './hash.js';

const encoder = new TextEncoder();
const SEED_DOMAIN = 'sc-ed25519-v1|';

export interface Identity {
  publicKey: Uint8Array;
  privateKey: Uint8Array; // the 32-byte seed - Ed25519's secret key format here
}

/** Derives this account's signing identity from its password. Deterministic - the same password always yields the same keypair, on any device. */
export async function deriveIdentity(password: string): Promise<Identity> {
  const seedHex = await sha256Hex(SEED_DOMAIN + password);
  const privateKey = hexToBytes(seedHex);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

/** Reconstructs an identity from a previously-derived seed (base64) - used to resume a session without asking for the password again. */
export function identityFromSeedB64(seedB64: string): Identity {
  const privateKey = b64ToBytes(seedB64);
  const publicKey = ed25519.getPublicKey(privateKey);
  return { publicKey, privateKey };
}

/** The seed as base64 - what gets persisted locally per-account. Treat like a password: never send this over the network. */
export function exportSeedB64(identity: Identity): string {
  return bytesToB64(identity.privateKey);
}

/** Raw 32-byte public key, base64 - this is exactly what gets registered and what the server imports to verify. */
export function exportPublicKeyRaw(publicKey: Uint8Array): string {
  return bytesToB64(publicKey);
}

/** sha256 hex of the raw public key bytes - shown to users so they can compare identities out-of-band. */
export function fingerprint(publicKey: Uint8Array): Promise<string> {
  return sha256HexBytes(publicKey);
}

/** Same fingerprint, computed from a base64 raw public key (e.g. one fetched over REST) rather than local key bytes. */
export function fingerprintFromRawB64(rawB64: string): Promise<string> {
  return sha256HexBytes(b64ToBytes(rawB64));
}

/** Signs the canonical message string (must match server's canonicalMessage()) and returns base64. */
export function signMessage(privateKey: Uint8Array, canonical: string): string {
  const sig = ed25519.sign(encoder.encode(canonical), privateKey);
  return bytesToB64(sig);
}

/** Verifies a signature against a raw base64 public key (e.g. a peer's registered key). */
export function verifyMessage(peerPublicKeyRawB64: string, canonical: string, sigB64: string): boolean {
  try {
    return ed25519.verify(b64ToBytes(sigB64), encoder.encode(canonical), b64ToBytes(peerPublicKeyRawB64));
  } catch {
    return false;
  }
}
