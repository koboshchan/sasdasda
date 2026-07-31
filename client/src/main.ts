// Bootstrap: loads/generates the local Ed25519 identity, resumes an
// existing session if one is stored, and wires the three screens together.
import { generateIdentity, exportIdentityBackup, importIdentityBackup, exportPublicKeyRaw } from './crypto/identity.js';
import * as api from './net/rest.js';
import { ChatSocket } from './net/ws.js';
import { getKv, setKv, getSession, clearSession } from './store/vault.js';
import { showAuthScreen, showRoomsScreen } from './ui/screens.js';
import { wireAuthScreen, type AuthResult } from './ui/auth.js';
import { wireRoomsScreen } from './ui/rooms.js';
import { wireChatScreen } from './ui/chat.js';
import { state } from './state.js';

async function ensureIdentity(): Promise<void> {
  const backup = await getKv<string>('identity');
  if (backup) {
    state.identity = await importIdentityBackup(backup);
    return;
  }
  const identity = await generateIdentity();
  await setKv('identity', await exportIdentityBackup(identity));
  state.identity = identity;
}

function connectSocket(token: string, chatCtrl: ReturnType<typeof wireChatScreen>): void {
  state.socket?.close();
  const socket = new ChatSocket(token);
  socket.onErrorEvent((err) => console.error(`WS error [${err.code}]: ${err.message}`));
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

async function applyIdentityMismatchCheck(registeredEdPubB64: string): Promise<void> {
  state.registeredEdPubB64 = registeredEdPubB64;
  if (!state.identity) {
    state.identityMismatch = true;
    return;
  }
  const localPub = await exportPublicKeyRaw(state.identity.publicKey);
  state.identityMismatch = localPub !== registeredEdPubB64;
}

async function main(): Promise<void> {
  await ensureIdentity();

  const chatCtrl = wireChatScreen();
  wireRoomsScreen((room) => chatCtrl.openRoom(room));
  wireAuthScreen(onLoggedIn);

  window.addEventListener('securecord:logout', () => {
    void handleLogout();
  });

  async function onLoggedIn(result: AuthResult): Promise<void> {
    state.username = result.username;
    await applyIdentityMismatchCheck(result.registeredEdPubB64);
    connectSocket(result.token, chatCtrl);
    showRoomsScreenAndRefresh();
  }

  async function handleLogout(): Promise<void> {
    try {
      await api.logout();
    } catch {
      // Best-effort - proceed with local cleanup regardless.
    }
    state.socket?.close();
    state.socket = null;
    state.username = null;
    state.currentRoom = null;
    state.peerKeys.clear();
    state.registeredEdPubB64 = null;
    state.identityMismatch = false;
    await clearSession();
    showAuthScreen();
  }

  // Resume an existing session, if any and still valid.
  const session = await getSession();
  if (session && session.expiresAt > Date.now()) {
    state.username = session.username;
    try {
      const { edPubB64 } = await api.getUserKey(session.username);
      await applyIdentityMismatchCheck(edPubB64);
      connectSocket(session.token, chatCtrl);
      showRoomsScreenAndRefresh();
      return;
    } catch {
      // Session token rejected server-side (expired/revoked) - fall through to login.
      await clearSession();
    }
  }

  showAuthScreen();
}

main().catch((err) => {
  console.error('Fatal startup error:', err);
});
