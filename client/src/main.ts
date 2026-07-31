// Bootstrap: resumes an existing session if one is stored, and wires the
// three screens together. There is no identity to load/generate at
// startup - the Ed25519 identity is derived from the account password at
// register/login time (see crypto/identity.ts::deriveIdentity and
// ui/auth.ts) and only reconstructed here, from the locally-persisted
// per-account seed, when resuming an already-logged-in session.
import { identityFromSeedB64 } from './crypto/identity.js';
import * as api from './net/rest.js';
import { ChatSocket } from './net/ws.js';
import { getSession, clearSession, getIdentitySeed, deleteIdentitySeed } from './store/vault.js';
import { showAuthScreen, showRoomsScreen } from './ui/screens.js';
import { wireAuthScreen, type AuthResult } from './ui/auth.js';
import { wireRoomsScreen } from './ui/rooms.js';
import { wireChatScreen } from './ui/chat.js';
import { state } from './state.js';

function connectSocket(token: string, chatCtrl: ReturnType<typeof wireChatScreen>): void {
  state.socket?.close();
  const socket = new ChatSocket(token);
  socket.onErrorEvent(chatCtrl.handleWsError);
  socket.onMessageEvent(chatCtrl.handleIncomingMessage);
  socket.connect();
  state.socket = socket;
}

// Shows the rooms screen and asks it to reload from the server. Must only
// ever be called once a session exists - the rooms screen's GET /api/rooms
// is authenticated, and calling it any earlier just produces a 401.
function showRoomsScreenAndRefresh(): void {
  showRoomsScreen();
  window.dispatchEvent(new CustomEvent('securecord:refresh-rooms'));
}

async function main(): Promise<void> {
  const chatCtrl = wireChatScreen();
  wireRoomsScreen((room) => chatCtrl.openRoom(room));
  wireAuthScreen(onLoggedIn);

  window.addEventListener('securecord:logout', () => {
    void handleLogout();
  });

  function onLoggedIn(result: AuthResult): void {
    state.username = result.username;
    connectSocket(result.token, chatCtrl);
    showRoomsScreenAndRefresh();
  }

  async function handleLogout(): Promise<void> {
    try {
      await api.logout();
    } catch {
      // Best-effort - proceed with local cleanup regardless.
    }
    const username = state.username;
    state.socket?.close();
    state.socket = null;
    state.username = null;
    state.currentRoom = null;
    state.peerKeys.clear();
    state.identity = null;
    // The derived seed is only meant to survive an active session (so a
    // page reload doesn't need the password again) - an explicit logout
    // removes it, so the private key material doesn't linger in IndexedDB
    // once the user has signed out. The next login re-derives it from the
    // password (see ui/auth.ts).
    if (username) await deleteIdentitySeed(username);
    await clearSession();
    showAuthScreen();
  }

  // Resume an existing session, if any and still valid.
  const session = await getSession();
  if (session && session.expiresAt > Date.now()) {
    const seedB64 = await getIdentitySeed(session.username);
    if (seedB64) {
      state.username = session.username;
      state.identity = identityFromSeedB64(seedB64);
      try {
        // No dedicated "is this session still valid" endpoint - GET
        // /api/rooms is authenticated, needs no proof-of-work, and is
        // exactly what the rooms screen needs next anyway, so it doubles
        // as the check. A rejected/expired token throws here and falls
        // through to a fresh login instead of opening a WebSocket that the
        // server would immediately reject.
        await api.listRooms();
        connectSocket(session.token, chatCtrl);
        showRoomsScreenAndRefresh();
        return;
      } catch {
        // Session token rejected server-side (expired/revoked) - fall through to login.
        state.identity = null;
        await clearSession();
      }
    } else {
      // No locally-persisted seed for this account (e.g. IndexedDB was
      // partially cleared) - there's no way to sign messages, so treat
      // this the same as no session at all rather than leaving the app in
      // a logged-in-but-can't-send state.
      await clearSession();
    }
  }

  showAuthScreen();
}

main().catch((err) => {
  console.error('Fatal startup error:', err);
});
