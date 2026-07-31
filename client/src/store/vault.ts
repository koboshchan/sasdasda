// IndexedDB-backed local vault: the identity keypair, per-room secret
// codes/AES keys, pinned peer public keys, and the current session. None of
// this is ever sent to the server except the deliberate, explicit "export
// identity" backup flow (see crypto/identity.ts) and the derived values
// (H2, RSA-wrapped hashes, signatures) that the rest of the app computes
// from it.
const DB_NAME = 'securecord';
const DB_VERSION = 2;

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (ev) => {
      const db = req.result;
      if (!db.objectStoreNames.contains('kv')) db.createObjectStore('kv');
      if (!db.objectStoreNames.contains('peers')) db.createObjectStore('peers', { keyPath: 'username' });

      // v1 -> v2: rooms are now keyed by [owner, roomId] instead of just
      // roomId, so that logging into a different account on this same
      // browser never surfaces rooms cached under a previous account (a
      // v1 database keyed by roomId alone had no such scoping). This is a
      // one-time reset of the local room cache - the server-side room
      // membership is untouched, and rejoining with the room's code
      // restores it.
      if (ev.oldVersion < 2 && db.objectStoreNames.contains('rooms')) {
        db.deleteObjectStore('rooms');
      }
      if (!db.objectStoreNames.contains('rooms')) {
        db.createObjectStore('rooms', { keyPath: ['owner', 'roomId'] });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function tx<T>(
  db: IDBDatabase,
  store: string,
  mode: IDBTransactionMode,
  run: (os: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const t = db.transaction(store, mode);
    const os = t.objectStore(store);
    const req = run(os);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

// --- Generic key-value (identity backup, current session) ---

export async function getKv<T>(key: string): Promise<T | undefined> {
  const db = await openDb();
  return tx<T | undefined>(db, 'kv', 'readonly', (os) => os.get(key));
}

export async function setKv<T>(key: string, value: T): Promise<void> {
  const db = await openDb();
  await tx(db, 'kv', 'readwrite', (os) => os.put(value, key));
}

export async function deleteKv(key: string): Promise<void> {
  const db = await openDb();
  await tx(db, 'kv', 'readwrite', (os) => os.delete(key));
}

// --- Session ---

export interface StoredSession {
  token: string;
  username: string;
  expiresAt: number;
}

export const getSession = () => getKv<StoredSession>('session');
export const setSession = (session: StoredSession) => setKv('session', session);
export const clearSession = () => deleteKv('session');

// --- Rooms: the secret code and derived H1 (the AES key) never leave here ---
//
// Keyed by [owner, roomId] (owner = the local username that created/joined
// it) rather than roomId alone, so that logging out and into a different
// account on the same device never shows the previous account's rooms -
// each account only ever sees rows it stored itself.

export interface StoredRoom {
  roomId: string; // H2
  owner: string; // the local username this room entry belongs to
  name: string; // decrypted display name
  h1: string; // sha256(code) hex - the AES-256 key, LOCAL ONLY
}

export async function putRoom(room: StoredRoom): Promise<void> {
  const db = await openDb();
  await tx(db, 'rooms', 'readwrite', (os) => os.put(room));
}

export async function listRoomsLocal(owner: string): Promise<StoredRoom[]> {
  const db = await openDb();
  const all = await tx<StoredRoom[]>(db, 'rooms', 'readonly', (os) => os.getAll());
  return all.filter((room) => room.owner === owner);
}

// --- Peers: trust-on-first-use pinning of Ed25519 public keys ---

export interface StoredPeer {
  username: string;
  edPubB64: string;
  fingerprint: string;
}

async function getPeer(username: string): Promise<StoredPeer | undefined> {
  const db = await openDb();
  return tx<StoredPeer | undefined>(db, 'peers', 'readonly', (os) => os.get(username));
}

async function putPeer(peer: StoredPeer): Promise<void> {
  const db = await openDb();
  await tx(db, 'peers', 'readwrite', (os) => os.put(peer));
}

export type PinResult =
  | { status: 'new' }
  | { status: 'match' }
  | { status: 'mismatch'; pinned: StoredPeer };

/**
 * Trust-on-first-use: pins a peer's public key the first time it's seen. On
 * every later sighting, compares against the pinned key rather than
 * silently trusting the server again - a mismatch means either the peer
 * re-registered, or the server is attempting to substitute a key, and the
 * caller must surface this rather than proceed quietly.
 */
export async function checkAndPinPeer(username: string, edPubB64: string, fp: string): Promise<PinResult> {
  const existing = await getPeer(username);
  if (!existing) {
    await putPeer({ username, edPubB64, fingerprint: fp });
    return { status: 'new' };
  }
  if (existing.edPubB64 === edPubB64) return { status: 'match' };
  return { status: 'mismatch', pinned: existing };
}

/** Explicit re-pin after the user has reviewed and accepted a key-change warning. */
export async function forceRepinPeer(username: string, edPubB64: string, fp: string): Promise<void> {
  await putPeer({ username, edPubB64, fingerprint: fp });
}
