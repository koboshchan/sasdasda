// Chat screen: renders history + live messages for the open room, sends
// signed+encrypted messages, and manages the local Ed25519 identity panel
// (fingerprint display, export/import for moving between devices).
//
// Rendering pipeline per message, strictly in this order:
//   1. Resolve the sender's Ed25519 public key (REST + trust-on-first-use
//      pin, see store/vault.ts::checkAndPinPeer). A pin mismatch is treated
//      as untrusted - the message is never decrypted, only flagged.
//   2. Verify the signature over the exact canonical string the server
//      checked (roomId|sender|ts|iv|ct). Anything that fails is rendered as
//      a visibly invalid row and never decrypted.
//   3. Only then AES-GCM-decrypt with the local room key (H1) and render
//      via textContent - never innerHTML, which is what made the original
//      index.html vulnerable to a stored-XSS via message text.
import { aesEncrypt, aesDecrypt, importAesKey, type EncBlob } from '../crypto/aes.js';
import {
  signMessage,
  verifyMessage,
  exportIdentityBackup,
  importIdentityBackup,
  exportPublicKeyRaw,
  fingerprint,
  fingerprintFromRawB64,
} from '../crypto/identity.js';
import * as api from '../net/rest.js';
import type { InboundMsgNew } from '../net/ws.js';
import { checkAndPinPeer, listRoomsLocal, setKv, type StoredRoom } from '../store/vault.js';
import { showRoomsScreen } from './screens.js';
import { state } from '../state.js';

function el<T extends HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

interface RenderableMessage {
  roomId: string;
  sender: string;
  iv: string;
  ct: string;
  ts: number;
  sig: string;
}

export interface ChatController {
  openRoom: (room: StoredRoom) => Promise<void>;
  handleIncomingMessage: (m: InboundMsgNew) => void;
}

export function wireChatScreen(): ChatController {
  const chatHeader = el<HTMLElement>('chat-header');
  const messagesBox = el<HTMLElement>('messages-box');
  const messageInput = el<HTMLInputElement>('message-input');
  const backBtn = el<HTMLElement>('back-to-rooms');
  const channelList = el<HTMLElement>('channel-list');
  const userDisplay = el<HTMLElement>('logged-user-display');
  const logoutBtn = el<HTMLButtonElement>('chat-logout-btn');
  const fpEl = el<HTMLElement>('identity-fingerprint');
  const exportBtn = el<HTMLButtonElement>('export-identity-btn');
  const importBtn = el<HTMLButtonElement>('import-identity-btn');
  const importFile = el<HTMLInputElement>('import-identity-file');
  const keyWarningBanner = el<HTMLElement>('key-warning-banner');

  let currentAesKey: CryptoKey | null = null;

  function updateIdentityMismatchBanner(): void {
    if (state.identityMismatch) {
      keyWarningBanner.textContent =
        "This browser's identity does not match your account's registered signing key. " +
        'Messages sent from here will be REJECTED by the server. Import your identity backup ' +
        '(from the device you originally signed up on) to fix this.';
      keyWarningBanner.style.display = 'block';
    } else {
      keyWarningBanner.style.display = 'none';
    }
  }

  async function refreshIdentityPanel(): Promise<void> {
    if (!state.identity) return;
    fpEl.textContent = await fingerprint(state.identity.publicKey);
    updateIdentityMismatchBanner();
  }

  async function renderChannelList(activeRoomId: string): Promise<void> {
    const rooms = state.username ? await listRoomsLocal(state.username) : [];
    channelList.innerHTML = '';
    for (const room of rooms) {
      const div = document.createElement('div');
      div.className = 'channel' + (room.roomId === activeRoomId ? ' active' : '');
      div.textContent = room.name; // textContent, not innerHTML
      div.addEventListener('click', () => {
        void openRoom(room);
      });
      channelList.appendChild(div);
    }
  }

  async function getSignerKey(username: string): Promise<{ edPubB64: string; mismatch: boolean }> {
    const cached = state.peerKeys.get(username);
    if (cached) return cached;

    const { edPubB64 } = await api.getUserKey(username);
    const fp = await fingerprintFromRawB64(edPubB64);
    const pin = await checkAndPinPeer(username, edPubB64, fp);

    const info = { edPubB64, fingerprint: fp, mismatch: pin.status === 'mismatch' };
    state.peerKeys.set(username, info);

    if (pin.status === 'mismatch') {
      // Deliberately does not overwrite the pin automatically - see
      // store/vault.ts::checkAndPinPeer. Surface it and let messages from
      // this sender render as untrusted until a human resolves it.
      console.warn(
        `SECURITY WARNING: ${username}'s signing key changed since it was first seen. ` +
          `Pinned fingerprint: ${pin.pinned.fingerprint}, new fingerprint: ${fp}. ` +
          'Messages from them are shown as unverified.',
      );
    }
    return info;
  }

  async function renderMessage(m: RenderableMessage): Promise<void> {
    const canonical = `${m.roomId}|${m.sender}|${m.ts}|${m.iv}|${m.ct}`;
    const keyInfo = await getSignerKey(m.sender);
    const valid = !keyInfo.mismatch && (await verifyMessage(keyInfo.edPubB64, canonical, m.sig));

    const row = document.createElement('div');
    row.className = 'message' + (valid ? '' : ' invalid-sig');

    const userEl = document.createElement('div');
    userEl.className = 'message-user';
    userEl.textContent = m.sender; // textContent, not innerHTML - see file header

    const textEl = document.createElement('div');
    textEl.className = 'message-text';

    if (!valid) {
      textEl.textContent = keyInfo.mismatch
        ? "[hidden: sender's signing key changed and is not yet re-verified]"
        : '[rejected: invalid signature]';
    } else if (currentAesKey) {
      try {
        const plaintext = await aesDecrypt(currentAesKey, { iv: m.iv, ct: m.ct } as EncBlob);
        const parsed = JSON.parse(plaintext) as { text: string; ts: number };
        textEl.textContent = parsed.text;
      } catch {
        textEl.textContent = '[failed to decrypt - wrong room key?]';
      }
    }

    row.appendChild(userEl);
    row.appendChild(textEl);
    messagesBox.appendChild(row);
    messagesBox.scrollTop = messagesBox.scrollHeight;
  }

  async function openRoom(room: StoredRoom): Promise<void> {
    state.currentRoom = room;
    currentAesKey = await importAesKey(room.h1);
    chatHeader.textContent = `# ${room.name}`;
    messagesBox.innerHTML = '';
    userDisplay.textContent = state.username ?? '';

    await renderChannelList(room.roomId);
    state.socket?.subscribeRoom(room.roomId);

    try {
      const { messages } = await api.getHistory(room.roomId, undefined, 50);
      for (const m of messages) await renderMessage(m);
    } catch (err) {
      console.error('Failed to load history', err);
    }
  }

  function handleIncomingMessage(m: InboundMsgNew): void {
    if (!state.currentRoom || m.roomId !== state.currentRoom.roomId) return;
    void renderMessage(m);
  }

  messageInput.addEventListener('keypress', (ev) => {
    if (ev.key === 'Enter') void handleSend();
  });

  async function handleSend(): Promise<void> {
    const text = messageInput.value.trim();
    if (!text || !state.currentRoom || !currentAesKey || !state.identity || !state.username) return;

    if (state.identityMismatch) {
      alert(
        "Can't send: this browser's identity does not match your account's registered key. " +
          'Import your identity backup first (see the panel in the sidebar).',
      );
      return;
    }

    const ts = Date.now();
    const { iv, ct } = await aesEncrypt(currentAesKey, JSON.stringify({ text, ts }));
    const canonical = `${state.currentRoom.roomId}|${state.username}|${ts}|${iv}|${ct}`;
    const sig = await signMessage(state.identity.privateKey, canonical);
    const clientRef = crypto.randomUUID();

    messageInput.value = '';
    try {
      await state.socket?.sendMessage({ roomId: state.currentRoom.roomId, iv, ct, ts, sig, clientRef });
    } catch (err) {
      console.error('Failed to send message', err);
    }
  }

  backBtn.addEventListener('click', () => {
    state.currentRoom = null;
    showRoomsScreen();
    window.dispatchEvent(new CustomEvent('securecord:refresh-rooms'));
  });

  logoutBtn.addEventListener('click', () => {
    window.dispatchEvent(new CustomEvent('securecord:logout'));
  });

  exportBtn.addEventListener('click', () => {
    void handleExportIdentity();
  });

  async function handleExportIdentity(): Promise<void> {
    if (!state.identity) return;
    const backup = await exportIdentityBackup(state.identity);
    const blob = new Blob([backup], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `securecord-identity-${state.username ?? 'export'}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  importBtn.addEventListener('click', () => importFile.click());
  importFile.addEventListener('change', () => {
    void handleImportIdentity();
  });

  async function handleImportIdentity(): Promise<void> {
    const file = importFile.files?.[0];
    importFile.value = '';
    if (!file) return;

    try {
      const text = await file.text();
      const identity = await importIdentityBackup(text);
      state.identity = identity;
      await setKv('identity', text);

      if (state.registeredEdPubB64) {
        const localPub = await exportPublicKeyRaw(identity.publicKey);
        state.identityMismatch = localPub !== state.registeredEdPubB64;
      }

      await refreshIdentityPanel();
      alert('Identity imported successfully.');
    } catch (err) {
      console.error(err);
      alert('Failed to import identity backup - is this a valid export file?');
    }
  }

  void refreshIdentityPanel();

  return { openRoom, handleIncomingMessage };
}
