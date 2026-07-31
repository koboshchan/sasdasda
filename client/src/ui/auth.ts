// Sign up / log in screen.
//
// Sign up: password is hashed once locally (PH = sha256(password)), sent to
// the server RSA-wrapped so it's never on the wire in the clear, alongside
// this device's Ed25519 public key.
//
// Log in: server issues a single-use salt; client computes
// proof = sha256(PH + salt) and sends only that - the password and PH never
// leave the device after registration.
import { sha256Hex } from '../crypto/hash.js';
import { rsaEncryptString } from '../crypto/rsa.js';
import { exportPublicKeyRaw } from '../crypto/identity.js';
import * as api from '../net/rest.js';
import { setSession } from '../store/vault.js';
import { bindPowProgress } from './pow-progress.js';
import { state } from '../state.js';

function el<T extends HTMLElement>(id: string): T {
  return document.getElementById(id) as T;
}

export interface AuthResult {
  username: string;
  token: string;
  registeredEdPubB64: string;
}

export function wireAuthScreen(onLoggedIn: (result: AuthResult) => void): void {
  let isLoginMode = false;

  const title = el<HTMLHeadingElement>('auth-title');
  const usernameInput = el<HTMLInputElement>('username-input');
  const passwordInput = el<HTMLInputElement>('password-input');
  const authBtn = el<HTMLButtonElement>('auth-btn');
  const errorEl = el<HTMLElement>('auth-error');
  const switchEl = el<HTMLElement>('auth-switch');
  const switchLabel = el<HTMLElement>('switch-txt-btn');
  const progress = bindPowProgress('auth-pow-progress', 'auth-pow-label', 'auth-pow-fill');

  function setMode(login: boolean, message?: string): void {
    isLoginMode = login;
    title.textContent = login ? 'Welcome Back' : 'Create Account';
    authBtn.textContent = login ? 'Log In' : 'Sign Up';
    switchLabel.textContent = login ? 'Need an account? Sign up' : 'Already have an account? Log in';
    errorEl.style.display = message ? 'block' : 'none';
    errorEl.textContent = message ?? '';
  }

  switchEl.addEventListener('click', () => setMode(!isLoginMode));

  authBtn.addEventListener('click', () => {
    void handleSubmit();
  });

  async function handleSubmit(): Promise<void> {
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    errorEl.style.display = 'none';

    if (!username || !password) {
      errorEl.textContent = 'Fill out all fields!';
      errorEl.style.display = 'block';
      return;
    }
    if (!state.identity) {
      errorEl.textContent = 'Local identity not ready yet - try again in a moment.';
      errorEl.style.display = 'block';
      return;
    }

    authBtn.disabled = true;
    progress.show();
    try {
      if (!isLoginMode) {
        const ph = await sha256Hex(password);
        const phEnc = await rsaEncryptString(ph);
        const edPubB64 = await exportPublicKeyRaw(state.identity.publicKey);
        await api.register(username, phEnc, edPubB64, progress.onProgress);
        setMode(true, 'Account created! You can now log in.');
        errorEl.style.color = 'var(--text-muted)';
      } else {
        const { salt } = await api.loginChallenge(username, progress.onProgress);
        const ph = await sha256Hex(password);
        const proof = await sha256Hex(ph + salt);
        const { token, expiresAt, edPubB64 } = await api.login(username, salt, proof, progress.onProgress);
        await setSession({ token, username, expiresAt });
        onLoggedIn({ username, token, registeredEdPubB64: edPubB64 });
      }
    } catch (err) {
      errorEl.style.color = 'var(--danger)';
      errorEl.textContent = err instanceof api.ApiError ? err.message : 'Something went wrong. Try again.';
      errorEl.style.display = 'block';
    } finally {
      authBtn.disabled = false;
      progress.hide();
    }
  }
}
