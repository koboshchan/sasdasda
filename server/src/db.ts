import { MongoClient, type Collection } from 'mongodb';
import { MONGO_URL } from './config.js';

export interface UserDoc {
  _id: string; // username
  ph: string; // sha256(password), hex - see README threat model
  edPub: string; // base64 raw Ed25519 public key
  createdAt: Date;
}

export interface SessionDoc {
  _id: string; // session token
  username: string;
  expiresAt: Date;
}

export interface RoomDoc {
  _id: string; // H2 = sha256(sha256(code)) - the room id, never the AES key
  nameEnc: { iv: string; ct: string }; // AES-GCM(H1, name), server can't read this
  createdBy: string;
  createdAt: Date;
}

export interface MembershipDoc {
  roomId: string;
  username: string;
  joinedAt: Date;
}

export interface MessageDoc {
  _id: string;
  roomId: string;
  sender: string;
  iv: string;
  ct: string;
  ts: number; // client-claimed timestamp, signed
  sig: string; // base64 Ed25519 signature
  serverTs: number; // server-observed order/time, not signed
}

let client: MongoClient | null = null;

export interface Collections {
  users: Collection<UserDoc>;
  sessions: Collection<SessionDoc>;
  rooms: Collection<RoomDoc>;
  memberships: Collection<MembershipDoc>;
  messages: Collection<MessageDoc>;
}

let collections: Collections | null = null;

export async function connectDb(): Promise<Collections> {
  if (collections) return collections;

  client = new MongoClient(MONGO_URL);
  await client.connect();
  const db = client.db();

  collections = {
    users: db.collection<UserDoc>('users'),
    sessions: db.collection<SessionDoc>('sessions'),
    rooms: db.collection<RoomDoc>('rooms'),
    memberships: db.collection<MembershipDoc>('memberships'),
    messages: db.collection<MessageDoc>('messages'),
  };

  await Promise.all([
    collections.sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    collections.memberships.createIndex({ roomId: 1, username: 1 }, { unique: true }),
    collections.messages.createIndex({ roomId: 1, serverTs: 1 }),
  ]);

  return collections;
}

export function getDb(): Collections {
  if (!collections) throw new Error('Database not connected yet - call connectDb() first');
  return collections;
}

export async function closeDb(): Promise<void> {
  await client?.close();
  client = null;
  collections = null;
}
