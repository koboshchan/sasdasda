// MongoDB's duplicate-key error (E11000) doesn't have its own exported
// class in the driver we depend on - it's a plain error with a `code`
// property. This is the shared duck-type check for it, used wherever a
// findOne-then-insertOne race needs to collapse cleanly into "already
// exists" instead of leaking as an uncaught 500.
export function isDuplicateKeyError(err: unknown): boolean {
  return typeof err === 'object' && err !== null && 'code' in err && (err as { code: unknown }).code === 11000;
}
