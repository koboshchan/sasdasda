// Client-side proof-of-work solver. Counts up in hex starting at 0,
// appending the counter as a string to the server's challenge, until
// sha256(challenge + nonce) ends in `difficulty` hex zeros. Must match
// server/src/pow.ts exactly - same digest, same "ends with", same counting.
import { sha256Hex } from './hash.js';

export interface PowSolution {
  challenge: string;
  nonce: string;
}

/** Expected attempts for a given difficulty, used only to estimate UI progress. */
export function expectedAttempts(difficulty: number): number {
  return 16 ** difficulty;
}

export async function solvePow(
  challenge: string,
  difficulty: number,
  onProgress?: (attempts: number, estimatedTotal: number) => void,
): Promise<PowSolution> {
  const target = '0'.repeat(difficulty);
  const estimatedTotal = expectedAttempts(difficulty);
  let i = 0;

  for (;;) {
    const nonce = i.toString(16);
    const digest = await sha256Hex(challenge + nonce);
    if (digest.endsWith(target)) return { challenge, nonce };

    i++;
    // Yield to the event loop periodically so a difficulty-5 solve doesn't
    // freeze the UI thread, and report progress for a "Verifying... N%" bar.
    if (i % 2000 === 0) {
      onProgress?.(i, estimatedTotal);
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }
}

export interface PowChallenge {
  challenge: string;
  difficulty: number;
  expiresAt: number;
}

/** Fetches a fresh challenge for `op` from the server. */
export async function fetchPowChallenge(op: string): Promise<PowChallenge> {
  const res = await fetch(`/api/pow?op=${encodeURIComponent(op)}`);
  if (!res.ok) throw new Error(`Failed to fetch PoW challenge for ${op}`);
  return res.json() as Promise<PowChallenge>;
}

/** Fetches a challenge for `op` and solves it in one step. */
export async function fetchAndSolvePow(
  op: string,
  onProgress?: (attempts: number, estimatedTotal: number) => void,
): Promise<PowSolution> {
  const { challenge, difficulty } = await fetchPowChallenge(op);
  return solvePow(challenge, difficulty, onProgress);
}
