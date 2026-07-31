// Registration and challenge-response login.
//
// The server only ever sees `ph = sha256(password)` (transported once,
// RSA-wrapped, at registration) and later `proof = sha256(ph + salt)` at
// login. It never sees the password itself, and never sees `ph` again in
// the clear after registration. See README for the residual risk this still
// carries (a DB leak of `ph` is password-equivalent) and why that's
// inherent to a challenge-response scheme over a shared secret.
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { getDb } from './db.js';
import { rsaDecryptToString } from './keys.js';
import { sha256Hex } from './pow.js';
import { LOGIN_SALT_TTL_MS, SESSION_TTL_MS } from './config.js';

const USERNAME_RE = /^[a-zA-Z0-9_-]{3,32}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;

export class AuthError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

// Pending login salts: single-use, short TTL, in-memory (mirrors pow.ts -
// a restart simply forces the client to restart the login handshake).
interface PendingLogin {
  salt: string;
  expiresAt: number;
}
const pendingLogins = new Map<string, PendingLogin>();

function validateUsername(username: string): void {
  if (!USERNAME_RE.test(username)) {
    throw new AuthError(400, 'Username must be 3-32 chars of letters, digits, _ or -');
  }
}

export async function registerUser(
  username: string,
  phEnc: string,
  edPubB64: string,
): Promise<void> {
  validateUsername(username);

  let ph: string;
  try {
    ph = rsaDecryptToString(phEnc);
  } catch {
    throw new AuthError(400, 'Malformed encrypted password hash');
  }
  if (!HEX64_RE.test(ph)) throw new AuthError(400, 'Malformed password hash');

  let edPubRaw: Buffer;
  try {
    edPubRaw = Buffer.from(edPubB64, 'base64');
  } catch {
    throw new AuthError(400, 'Malformed public key');
  }
  if (edPubRaw.length !== 32) throw new AuthError(400, 'Ed25519 public key must be 32 bytes');

  const db = getDb();
  const existing = await db.users.findOne({ _id: username });
  if (existing) throw new AuthError(409, 'Username already taken');

  await db.users.insertOne({ _id: username, ph, edPub: edPubB64, createdAt: new Date() });
}

/**
 * Issues a fresh single-use salt for a login attempt. Always succeeds, even
 * for an unknown username, so the response shape can't be used to enumerate
 * registered accounts - the mismatch simply surfaces at verifyLogin().
 */
export function requestLoginSalt(username: string): string {
  validateUsername(username);
  const salt = sha256Hex(randomBytes(32));
  pendingLogins.set(username, { salt, expiresAt: Date.now() + LOGIN_SALT_TTL_MS });
  return salt;
}

export interface LoginResult {
  token: string;
  expiresAt: number;
  edPubB64: string;
}

export async function verifyLogin(
  username: string,
  salt: string,
  proof: string,
): Promise<LoginResult> {
  const pending = pendingLogins.get(username);
  // Burn immediately regardless of outcome - a captured (salt, proof) pair
  // can never be replayed, successful or not.
  pendingLogins.delete(username);

  if (!pending || pending.salt !== salt || Date.now() > pending.expiresAt) {
    throw new AuthError(401, 'Login challenge expired or invalid; request a new one');
  }
  if (!HEX64_RE.test(proof)) throw new AuthError(400, 'Malformed proof');

  const db = getDb();
  const user = await db.users.findOne({ _id: username });
  if (!user) throw new AuthError(401, 'Invalid username or password');

  const expected = sha256Hex(user.ph + salt);
  const expectedBuf = Buffer.from(expected, 'utf8');
  const proofBuf = Buffer.from(proof, 'utf8');
  const match = expectedBuf.length === proofBuf.length && timingSafeEqual(expectedBuf, proofBuf);
  if (!match) throw new AuthError(401, 'Invalid username or password');

  const token = randomBytes(32).toString('hex');
  const expiresAt = Date.now() + SESSION_TTL_MS;
  await db.sessions.insertOne({ _id: token, username, expiresAt: new Date(expiresAt) });

  return { token, expiresAt, edPubB64: user.edPub };
}

export async function logoutSession(token: string): Promise<void> {
  await getDb().sessions.deleteOne({ _id: token });
}

/** Resolves a bearer token to a username, or null if absent/expired. */
export async function resolveSession(token: string | undefined): Promise<string | null> {
  if (!token) return null;
  const db = getDb();
  const session = await db.sessions.findOne({ _id: token });
  if (!session) return null;
  if (session.expiresAt.getTime() <= Date.now()) return null;
  return session.username;
}

export async function getUserPublicKey(username: string): Promise<string | null> {
  const user = await getDb().users.findOne({ _id: username });
  return user?.edPub ?? null;
}

// Sweep expired pending logins so the Map can't grow unbounded.
const sweepInterval = setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of pendingLogins) {
    if (now > entry.expiresAt) pendingLogins.delete(key);
  }
}, LOGIN_SALT_TTL_MS);
sweepInterval.unref();
