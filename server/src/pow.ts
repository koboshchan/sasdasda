// Proof-of-work anti-bot gate. The server hands out a sha256(randomBytes)
// challenge; the client must find a hex nonce such that
// sha256(challenge + nonce) ends in `difficulty` zero hex digits, counting
// up from 0 in hex. Each challenge is single-use and expires after
// POW_TTL_MS. State is an in-memory Map: it does not survive a restart
// (outstanding challenges are simply invalidated, and clients re-request)
// and does not scale past one server instance - acceptable for this project.
import { createHash, randomBytes } from 'node:crypto';
import { POW_TTL_MS } from './config.js';

export type PowOp = 'register' | 'createRoom' | 'login' | 'joinRoom' | 'sendMessage' | 'history';

// Rough expected work at 16^d hashes; sendMessage difficulty is kept low
// because the client is expected to pre-solve it against the ack of the
// previous message so sending never blocks on a round trip (see ws/hub.ts).
export const POW_DIFFICULTY: Record<PowOp, number> = {
  register: 4,
  createRoom: 4,
  login: 4,
  joinRoom: 3,
  sendMessage: 2,
  history: 1,
};

interface ChallengeEntry {
  op: PowOp;
  difficulty: number;
  expiresAt: number;
  used: boolean;
}

const challenges = new Map<string, ChallengeEntry>();

export function sha256Hex(input: string | Buffer): string {
  return createHash('sha256').update(input).digest('hex');
}

export interface IssuedChallenge {
  challenge: string;
  difficulty: number;
  expiresAt: number;
}

export function issueChallenge(op: PowOp): IssuedChallenge {
  const challenge = sha256Hex(randomBytes(32));
  const difficulty = POW_DIFFICULTY[op];
  const expiresAt = Date.now() + POW_TTL_MS;
  challenges.set(challenge, { op, difficulty, expiresAt, used: false });
  return { challenge, difficulty, expiresAt };
}

export interface PowSubmission {
  challenge: string;
  nonce: string;
}

/**
 * Verifies a solved challenge for the given operation and burns it so it
 * can never be reused (replay-proof), regardless of pass/fail.
 */
export function verifyAndBurn(op: PowOp, submission: PowSubmission | undefined | null): boolean {
  if (!submission || !submission.challenge || !submission.nonce) return false;
  const entry = challenges.get(submission.challenge);
  if (!entry) return false;

  // Single-use: remove immediately so a captured valid solution cannot be
  // replayed even if verification below fails for an unrelated reason.
  challenges.delete(submission.challenge);

  if (entry.used) return false;
  if (entry.op !== op) return false;
  if (Date.now() > entry.expiresAt) return false;

  const digest = sha256Hex(submission.challenge + submission.nonce);
  return digest.endsWith('0'.repeat(entry.difficulty));
}

// Periodic sweep of expired-but-unused challenges to bound memory growth.
const sweepInterval = setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of challenges) {
    if (now > entry.expiresAt) challenges.delete(key);
  }
}, POW_TTL_MS);
sweepInterval.unref();
