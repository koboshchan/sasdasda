// Client-side proof-of-work solver. Counts up in hex starting at 0,
// appending the counter as a string to the server's challenge, until
// sha256(challenge + nonce) ends in `difficulty` hex zeros. Must match
// server/src/pow.ts exactly - same digest, same "ends with", same counting.
//
// The hot loop uses @noble/hashes' synchronous sha256 rather than
// crypto/hash.ts's WebCrypto sha256Hex: awaiting crypto.subtle.digest per
// iteration measured at ~83k hashes/sec, which made difficulty 5 a ~13s
// solve - impractical for register/createRoom. Synchronous hashing is
// roughly 14x faster, making difficulty 5 a ~1s solve instead. Every other
// use of sha256 in this app (H1/H2 derivation, password hashing, RSA/AES/
// Ed25519 key material) stays on WebCrypto via hash.ts - only this
// brute-force loop needed the swap.
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';

const encoder = new TextEncoder();

function sha256HexSync(input: string): string {
  return bytesToHex(sha256(encoder.encode(input)));
}

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
    const digest = sha256HexSync(challenge + nonce);
    if (digest.endsWith(target)) return { challenge, nonce };

    i++;
    // Yield to the event loop periodically so a difficulty-5 solve doesn't
    // freeze the UI thread, and report progress for a "Verifying... N%" bar.
    // Checked far less often than the old WebCrypto loop since each
    // iteration is now much cheaper - checking every 2k would mostly just
    // add setTimeout scheduling overhead.
    if (i % 50000 === 0) {
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
