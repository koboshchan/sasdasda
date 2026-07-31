// RSA-4096/OAEP-SHA256 keypair, generated once on first boot and persisted
// to disk (KEYS_DIR, bind-mounted from ./server/data/keys on the host so it
// survives container rebuilds). Used only to transport small hex-string
// hashes (room ids, password hashes) from the client - see docs in README.
import {
  constants as cryptoConstants,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  privateDecrypt,
  type KeyObject,
} from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import path from 'node:path';
import { KEYS_DIR } from './config.js';

const PRIV_PATH = path.join(KEYS_DIR, 'rsa_priv.pem');
const PUB_PATH = path.join(KEYS_DIR, 'rsa_pub.pem');

export interface ServerKeys {
  privateKey: KeyObject;
  publicKey: KeyObject;
  /** Base64-encoded SPKI DER, for the client to import via crypto.subtle.importKey('spki', ...). */
  spkiB64: string;
  /** sha256 hex of the SPKI DER, shown to users as a fingerprint for out-of-band verification. */
  fingerprint: string;
}

let cached: ServerKeys | null = null;

function generateAndSave(): { privateKey: KeyObject; publicKey: KeyObject } {
  mkdirSync(KEYS_DIR, { recursive: true });
  const { privateKey, publicKey } = generateKeyPairSync('rsa', {
    modulusLength: 4096,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  writeFileSync(PRIV_PATH, privateKey, { mode: 0o600 });
  writeFileSync(PUB_PATH, publicKey, { mode: 0o644 });
  chmodSync(PRIV_PATH, 0o600);
  return {
    privateKey: createPrivateKey(privateKey),
    publicKey: createPublicKey(publicKey),
  };
}

function loadExisting(): { privateKey: KeyObject; publicKey: KeyObject } {
  const privPem = readFileSync(PRIV_PATH, 'utf8');
  const pubPem = readFileSync(PUB_PATH, 'utf8');
  return {
    privateKey: createPrivateKey(privPem),
    publicKey: createPublicKey(pubPem),
  };
}

/** Loads the RSA keypair from disk, generating it on first run. Idempotent, cached in memory. */
export function getServerKeys(): ServerKeys {
  if (cached) return cached;

  const { privateKey, publicKey } = existsSync(PRIV_PATH) && existsSync(PUB_PATH)
    ? loadExisting()
    : generateAndSave();

  const spkiDer = publicKey.export({ type: 'spki', format: 'der' }) as Buffer;
  const spkiB64 = spkiDer.toString('base64');
  const fingerprint = createHash('sha256').update(spkiDer).digest('hex');

  cached = { privateKey, publicKey, spkiB64, fingerprint };
  return cached;
}

/**
 * Decrypts a base64 RSA-OAEP(SHA-256) ciphertext produced by the client and
 * returns the plaintext as a utf8 string (callers pass hex-encoded hashes).
 */
export function rsaDecryptToString(ciphertextB64: string): string {
  const { privateKey } = getServerKeys();
  const ciphertext = Buffer.from(ciphertextB64, 'base64');
  const plaintext = privateDecrypt(
    {
      key: privateKey,
      padding: cryptoConstants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha256',
    },
    ciphertext,
  );
  return plaintext.toString('utf8');
}
