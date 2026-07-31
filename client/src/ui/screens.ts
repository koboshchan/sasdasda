// Top-level screen visibility. Only one of these three is ever shown.
function el(id: string): HTMLElement {
  const found = document.getElementById(id);
  if (!found) throw new Error(`Missing #${id} in index.html`);
  return found;
}

export function showAuthScreen(): void {
  el('auth-screen').style.display = 'flex';
  el('rooms-screen').style.display = 'none';
  el('app-container').style.display = 'none';
}

export function showRoomsScreen(): void {
  el('auth-screen').style.display = 'none';
  el('rooms-screen').style.display = 'flex';
  el('app-container').style.display = 'none';
}

export function showChatScreen(): void {
  el('auth-screen').style.display = 'none';
  el('rooms-screen').style.display = 'none';
  el('app-container').style.display = 'flex';
}
