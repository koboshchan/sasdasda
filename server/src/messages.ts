// Message persistence and signature enforcement. The server stores and
// forwards only { iv, ct } - the AES-GCM ciphertext and its nonce. It can
// never decrypt these (it never has H1, the AES key). What it *can* and
// must do is verify the Ed25519 signature over the message before accepting
// it, using the sender's public key registered at signup; anything unsigned
// or with an invalid signature is rejected and never written to the DB.
//
// A valid signature proves authorship, not freshness: resubmitting an
// old, already-stored (roomId, sender, ts, iv, ct, sig) tuple verifies just
// as well the second time, since it's byte-identical to the first. To stop
// that replay, `_id` is derived deterministically from the signed content
// rather than a fresh random UUID, so an identical resubmission collides on
// insert (Mongo's unique _id index) instead of quietly becoming a second
// message. Two distinct legitimate messages would only collide if roomId,
// sender, ts (millisecond) AND the 12 random IV bytes all matched -
// astronomically unlikely.
import { getDb, type MessageDoc } from './db.js';
import { getUserPublicKey } from './auth.js';
import { verifyEd25519 } from './sig.js';
import { sha256Hex } from './pow.js';
import { isDuplicateKeyError } from './mongoErrors.js';

export interface IncomingMessage {
  roomId: string;
  sender: string;
  iv: string;
  ct: string;
  ts: number;
  sig: string;
}

export class MessageRejected extends Error {}

// How far a claimed `ts` may drift from the server's own clock. Bounds how
// far in the future an attacker could usefully pre-sign a message, and
// stops a message from being back/post-dated to distort room ordering.
const TS_WINDOW_MS = 5 * 60 * 1000;

/** The exact byte string the client signs and the server re-derives to verify. */
export function canonicalMessage(m: Pick<IncomingMessage, 'roomId' | 'sender' | 'ts' | 'iv' | 'ct'>): string {
  return `${m.roomId}|${m.sender}|${m.ts}|${m.iv}|${m.ct}`;
}

function isValidShape(m: IncomingMessage): boolean {
  return (
    typeof m.roomId === 'string' &&
    typeof m.sender === 'string' &&
    typeof m.iv === 'string' &&
    typeof m.ct === 'string' &&
    typeof m.ts === 'number' &&
    Number.isFinite(m.ts) &&
    typeof m.sig === 'string' &&
    m.sig.length > 0
  );
}

/**
 * Verifies signature and persists. Caller (ws/hub.ts) must already have
 * checked session validity, room membership, and proof-of-work before
 * calling this - this function only handles the signature/storage step.
 * Throws MessageRejected (never stores anything) if the signature is
 * missing, does not verify against the sender's registered public key, the
 * timestamp is out of window, or this exact message was already stored.
 */
export async function verifyAndPersistMessage(input: IncomingMessage): Promise<MessageDoc> {
  if (!isValidShape(input)) throw new MessageRejected('Malformed message');
  if (Math.abs(Date.now() - input.ts) > TS_WINDOW_MS) throw new MessageRejected('Timestamp too far from server time');

  const edPubB64 = await getUserPublicKey(input.sender);
  if (!edPubB64) throw new MessageRejected('Unknown sender');

  const data = canonicalMessage(input);
  const ok = await verifyEd25519(edPubB64, data, input.sig);
  if (!ok) throw new MessageRejected('Invalid or missing signature');

  const doc: MessageDoc = {
    _id: sha256Hex(data),
    roomId: input.roomId,
    sender: input.sender,
    iv: input.iv,
    ct: input.ct,
    ts: input.ts,
    sig: input.sig,
    serverTs: Date.now(),
  };

  try {
    await getDb().messages.insertOne(doc);
  } catch (err) {
    if (isDuplicateKeyError(err)) throw new MessageRejected('Duplicate message (replay)');
    throw err;
  }

  return doc;
}

export async function getHistory(
  roomId: string,
  before: number | undefined,
  limit: number,
): Promise<MessageDoc[]> {
  const query: Record<string, unknown> = { roomId };
  if (before !== undefined) query.serverTs = { $lt: before };

  const docs = await getDb()
    .messages.find(query)
    .sort({ serverTs: -1 })
    .limit(Math.min(Math.max(limit, 1), 200))
    .toArray();

  return docs.reverse(); // ascending, ready to render top-to-bottom
}
