// Room lifecycle. The server only ever sees H2 = sha256(sha256(code)) - the
// AES key (sha256(code)) never leaves the client, and the room's display
// name is stored pre-encrypted under that key too, so a DB read reveals
// neither the code nor the name.
import { getDb } from './db.js';
import { rsaDecryptToString } from './keys.js';
import { AuthError } from './auth.js';

const HEX64_RE = /^[0-9a-f]{64}$/;

export interface EncBlob {
  iv: string;
  ct: string;
}

function decryptRoomId(roomIdEnc: string): string {
  let h2: string;
  try {
    h2 = rsaDecryptToString(roomIdEnc);
  } catch {
    throw new AuthError(400, 'Malformed encrypted room id');
  }
  if (!HEX64_RE.test(h2)) throw new AuthError(400, 'Malformed room id');
  return h2;
}

function isEncBlob(value: unknown): value is EncBlob {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof (value as EncBlob).iv === 'string' &&
    typeof (value as EncBlob).ct === 'string'
  );
}

export async function createRoom(
  username: string,
  roomIdEnc: string,
  nameEnc: unknown,
): Promise<{ roomId: string }> {
  if (!isEncBlob(nameEnc)) throw new AuthError(400, 'Malformed encrypted room name');
  const roomId = decryptRoomId(roomIdEnc);

  const db = getDb();
  const existing = await db.rooms.findOne({ _id: roomId });
  if (existing) throw new AuthError(409, 'A room with this code already exists');

  await db.rooms.insertOne({ _id: roomId, nameEnc, createdBy: username, createdAt: new Date() });
  await db.memberships.insertOne({ roomId, username, joinedAt: new Date() });

  return { roomId };
}

export async function joinRoom(
  username: string,
  roomIdEnc: string,
): Promise<{ roomId: string; nameEnc: EncBlob }> {
  const roomId = decryptRoomId(roomIdEnc);

  const db = getDb();
  const room = await db.rooms.findOne({ _id: roomId });
  // Deliberately identical to "malformed/unknown room" - do not distinguish
  // a wrong code from a nonexistent room, which would otherwise let an
  // attacker probe codes against a valid-room oracle.
  if (!room) throw new AuthError(404, 'Room not found');

  await db.memberships.updateOne(
    { roomId, username },
    { $setOnInsert: { roomId, username, joinedAt: new Date() } },
    { upsert: true },
  );

  return { roomId, nameEnc: room.nameEnc };
}

export async function listRooms(
  username: string,
): Promise<Array<{ roomId: string; nameEnc: EncBlob; joinedAt: Date }>> {
  const db = getDb();
  const memberships = await db.memberships.find({ username }).toArray();
  if (memberships.length === 0) return [];

  const rooms = await db.rooms
    .find({ _id: { $in: memberships.map((m) => m.roomId) } })
    .toArray();
  const roomsById = new Map(rooms.map((r) => [r._id, r]));

  return memberships
    .filter((m) => roomsById.has(m.roomId))
    .map((m) => ({
      roomId: m.roomId,
      nameEnc: roomsById.get(m.roomId)!.nameEnc,
      joinedAt: m.joinedAt,
    }));
}

export async function isMember(username: string, roomId: string): Promise<boolean> {
  const membership = await getDb().memberships.findOne({ roomId, username });
  return membership !== null;
}
