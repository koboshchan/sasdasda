// Small in-memory token-bucket rate limiter, keyed by an arbitrary string
// (callers namespace their own keys, e.g. `send:${username}`). Each bucket
// refills continuously at `refillPerSec` tokens/sec up to `capacity`; a call
// to take() consumes one token if available. This is the *volume* control
// that sits alongside proof-of-work: PoW makes each individual request cost
// something (anti-bot), this caps how many an already-authenticated,
// already-PoW-paying user can make per second (anti-flood) - PoW difficulty
// alone can't do that job without becoming so expensive it breaks normal use.
interface Bucket {
  tokens: number;
  lastRefill: number;
}

const buckets = new Map<string, Bucket>();

// Buckets untouched for this long are evicted so memory doesn't grow with
// every key (e.g. username) that was ever seen once.
const IDLE_TTL_MS = 10 * 60 * 1000;

export function take(key: string, capacity: number, refillPerSec: number): boolean {
  const now = Date.now();
  let bucket = buckets.get(key);

  if (!bucket) {
    bucket = { tokens: capacity, lastRefill: now };
    buckets.set(key, bucket);
  } else {
    const elapsedSec = (now - bucket.lastRefill) / 1000;
    bucket.tokens = Math.min(capacity, bucket.tokens + elapsedSec * refillPerSec);
    bucket.lastRefill = now;
  }

  if (bucket.tokens < 1) return false;
  bucket.tokens -= 1;
  return true;
}

const sweepInterval = setInterval(() => {
  const now = Date.now();
  for (const [key, bucket] of buckets) {
    if (now - bucket.lastRefill > IDLE_TTL_MS) buckets.delete(key);
  }
}, IDLE_TTL_MS);
sweepInterval.unref();
