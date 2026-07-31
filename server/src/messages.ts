// Message persistence and signature enforcement. The server stores and
// forwards only { iv, ct } - the AES-GCM ciphertext and its nonce. It can
// never decrypt these (it never has H1, the AES key). What it *can* and
// must do is verify the Ed25519 signature over the message before accepting
// it, using the sender's public key registered at signup; anything unsigned
// or with an invalid signature is rejected and never written to the DB.
import { randomUUID } from 'node:crypto';
import { getDb, type MessageDoc } from './db.js';
import { getUserPublicKey } from './auth.js';
import { verifyEd25519 } from './sig.js';

export interface IncomingMessage {
  roomId: string;
  sender: string;
  iv: string;
  ct: string;
  ts: number;
  sig: string;
}

export class MessageRejected extends Error {}

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
 * missing or does not verify against the sender's registered public key.
 */
export async function verifyAndPersistMessage(input: IncomingMessage): Promise<MessageDoc> {
  if (!isValidShape(input)) throw new MessageRejected('Malformed message');

  const edPubB64 = await getUserPublicKey(input.sender);
  if (!edPubB64) throw new MessageRejected('Unknown sender');

  const data = canonicalMessage(input);
  const ok = await verifyEd25519(edPubB64, data, input.sig);
  if (!ok) throw new MessageRejected('Invalid or missing signature');

  const doc: MessageDoc = {
    _id: randomUUID(),
    roomId: input.roomId,
    sender: input.sender,
    iv: input.iv,
    ct: input.ct,
    ts: input.ts,
    sig: input.sig,
    serverTs: Date.now(),
  };

  await getDb().messages.insertOne(doc);
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
