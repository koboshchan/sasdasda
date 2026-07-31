// Rooms screen: list rooms this device knows about, create a new room, or
// join an existing one with its secret code.
//
// The code never leaves this device. H1 = sha256(code) is the AES key;
// H2 = sha256(H1) is the only thing the server ever sees (RSA-wrapped), and
// it's what identifies the room. The display name is itself encrypted
// under H1 before it's sent, so a server-side read reveals neither the
// code nor the room's name.
import { sha256Hex } from '../crypto/hash.js';
import { importAesKey, aesEncrypt, aesDecrypt } from '../crypto/aes.js';
import { rsaEncryptString } from '../crypto/rsa.js';
import * as api from '../net/rest.js';
import { putRoom, listRoomsLocal, type StoredRoom } from '../store/vault.js';
import { bindPowProgress } from './pow-progress.js';
import { showChatScreen } from './screens.js';

function el<T extends HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

const CODE_CHARSET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const CODE_LENGTH = 10;

/**
 * Generates a random 10-char [A-Za-z0-9] code. Uses rejection sampling
 * (discarding bytes >= the largest multiple of 62 below 256) rather than a
 * plain modulo, so every character stays uniformly distributed instead of
 * slightly favoring the low end of the charset.
 */
function randomCode(): string {
  const maxValid = 256 - (256 % CODE_CHARSET.length);
  let result = '';
  while (result.length < CODE_LENGTH) {
    const batch = crypto.getRandomValues(new Uint8Array(CODE_LENGTH - result.length));
    for (const b of batch) {
      if (b < maxValid) result += CODE_CHARSET[b % CODE_CHARSET.length];
    }
  }
  return result;
}

export function wireRoomsScreen(onOpenRoom: (room: StoredRoom) => void): void {
  const listEl = el<HTMLUListElement>('rooms-list');
  const emptyEl = el<HTMLElement>('rooms-empty');
  const nameInput = el<HTMLInputElement>('create-room-name');
  const codeInput = el<HTMLInputElement>('create-room-code');
  const createBtn = el<HTMLButtonElement>('create-room-btn');
  const revealEl = el<HTMLElement>('create-room-reveal');
  const joinCodeInput = el<HTMLInputElement>('join-room-code');
  const joinBtn = el<HTMLButtonElement>('join-room-btn');
  const errorEl = el<HTMLElement>('rooms-error');
  const logoutBtn = el<HTMLButtonElement>('rooms-logout-btn');
  const progress = bindPowProgress('rooms-pow-progress', 'rooms-pow-label', 'rooms-pow-fill');

  let localRooms: StoredRoom[] = [];

  function showError(message: string): void {
    errorEl.textContent = message;
    errorEl.style.display = 'block';
  }
  function clearError(): void {
    errorEl.style.display = 'none';
  }

  async function refresh(): Promise<void> {
    localRooms = await listRoomsLocal();
    let serverCount = 0;
    try {
      const { rooms } = await api.listRooms();
      serverCount = rooms.length;
    } catch {
      // Non-fatal: fall back to showing local rooms only.
    }

    listEl.innerHTML = '';
    for (const room of localRooms) {
      const li = document.createElement('li');
      li.textContent = room.name; // textContent only - never innerHTML - see index.html XSS note
      li.addEventListener('click', () => {
        onOpenRoom(room);
        showChatScreen();
      });
      listEl.appendChild(li);
    }

    const extra = serverCount - localRooms.length;
    if (localRooms.length === 0) {
      emptyEl.textContent =
        extra > 0
          ? `No rooms on this device yet. You are a member of ${extra} room(s) from another device - rejoin below with their code to access them here.`
          : 'No rooms yet - create one or join with a code.';
      emptyEl.style.display = 'block';
    } else {
      emptyEl.style.display = extra > 0 ? 'block' : 'none';
      if (extra > 0) {
        emptyEl.textContent = `You are a member of ${extra} additional room(s) from another device - rejoin below with their code to access them here.`;
      }
    }
  }

  createBtn.addEventListener('click', () => {
    void handleCreate();
  });

  async function handleCreate(): Promise<void> {
    clearError();
    revealEl.style.display = 'none';
    const name = nameInput.value.trim();
    if (!name) return showError('Room name is required.');

    const generated = codeInput.value.trim().length === 0;
    const code = generated ? randomCode() : codeInput.value.trim();

    createBtn.disabled = true;
    progress.show();
    try {
      const h1 = await sha256Hex(code);
      const h2 = await sha256Hex(h1);
      const aesKey = await importAesKey(h1);
      const nameEnc = await aesEncrypt(aesKey, name);
      const roomIdEnc = await rsaEncryptString(h2);

      const { roomId } = await api.createRoom(roomIdEnc, nameEnc, progress.onProgress);
      await putRoom({ roomId, name, h1 });

      nameInput.value = '';
      codeInput.value = '';
      if (generated) {
        revealEl.textContent = `Room code (save this - it will not be shown again): ${code}`;
        revealEl.style.display = 'block';
      }
      await refresh();
    } catch (err) {
      showError(err instanceof api.ApiError ? err.message : 'Failed to create room.');
    } finally {
      createBtn.disabled = false;
      progress.hide();
    }
  }

  joinBtn.addEventListener('click', () => {
    void handleJoin();
  });

  async function handleJoin(): Promise<void> {
    clearError();
    const code = joinCodeInput.value.trim();
    if (!code) return showError('Enter a room code.');

    joinBtn.disabled = true;
    progress.show();
    try {
      const h1 = await sha256Hex(code);
      const h2 = await sha256Hex(h1);
      const roomIdEnc = await rsaEncryptString(h2);

      const { roomId, nameEnc } = await api.joinRoom(roomIdEnc, progress.onProgress);
      const aesKey = await importAesKey(h1);

      let name: string;
      try {
        name = await aesDecrypt(aesKey, nameEnc);
      } catch {
        showError('Joined, but failed to decrypt the room name - double check the code.');
        return;
      }

      await putRoom({ roomId, name, h1 });
      joinCodeInput.value = '';
      await refresh();
    } catch (err) {
      showError(err instanceof api.ApiError ? err.message : 'Failed to join room.');
    } finally {
      joinBtn.disabled = false;
      progress.hide();
    }
  }

  logoutBtn.addEventListener('click', () => {
    window.dispatchEvent(new CustomEvent('securecord:logout'));
  });

  window.addEventListener('securecord:refresh-rooms', () => {
    void refresh();
  });

  // Deliberately no eager refresh() here - this screen is wired up at app
  // bootstrap, before login, when there's no session token yet. Calling
  // the authenticated GET /api/rooms at that point would always 401.
  // main.ts dispatches 'securecord:refresh-rooms' once a session exists,
  // right before actually showing this screen.
}
