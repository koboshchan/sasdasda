// Shared in-memory state for the running session. Long-lived secrets (the
// identity keypair, room codes/AES keys, the session token) are persisted in
// store/vault.ts (IndexedDB); this module just holds live handles to them
// plus per-session caches for the current page load.
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
  /** The Ed25519 public key the server has on file for the logged-in account (from the login response). */
  registeredEdPubB64: string | null;
  /**
   * True when this browser's local identity doesn't match the Ed25519 key
   * the server has on file for the logged-in account (e.g. a fresh browser
   * profile that hasn't imported the account's identity backup yet).
   * Every message signed from this device would fail server verification,
   * so sending is blocked until the correct identity is imported.
   */
  identityMismatch: boolean;
}

export const state: AppState = {
  identity: null,
  username: null,
  socket: null,
  currentRoom: null,
  peerKeys: new Map(),
  registeredEdPubB64: null,
  identityMismatch: false,
};
