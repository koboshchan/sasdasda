// Shared in-memory state for the running session. Long-lived secrets (the
// derived identity seed, room codes/AES keys, the session token) are
// persisted in store/vault.ts (IndexedDB); this module just holds live
// handles to them plus per-session caches for the current page load.
import type { Identity } from './crypto/identity.js';
import type { ChatSocket } from './net/ws.js';
import type { StoredRoom } from './store/vault.js';

export interface PeerKeyInfo {
  edPubB64: string;
  fingerprint: string;
  mismatch: boolean;
}

export interface AppState {
  identity: Identity | null;
  username: string | null;
  socket: ChatSocket | null;
  currentRoom: StoredRoom | null;
  /** Per-session cache of verified/pinned peer signing keys, keyed by username. */
  peerKeys: Map<string, PeerKeyInfo>;
}

export const state: AppState = {
  identity: null,
  username: null,
  socket: null,
  currentRoom: null,
  peerKeys: new Map(),
};
