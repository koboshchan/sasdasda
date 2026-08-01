import { Router, type Request, type Response } from 'express';
import { getServerKeys } from '../keys.js';
import { issueChallenge, verifyAndBurn, POW_DIFFICULTY, type PowOp, type PowSubmission } from '../pow.js';
import {
  AuthError,
  registerUser,
  requestLoginSalt,
  verifyLogin,
  logoutSession,
  getUserPublicKey,
} from '../auth.js';
import { createRoom, joinRoom, listRooms, isMember, sharesRoomWith } from '../rooms.js';
import { getHistory } from '../messages.js';
import { requireAuth, requirePow } from '../middleware.js';

export const apiRouter = Router();

function handleAuthError(err: unknown, res: Response): void {
  if (err instanceof AuthError) {
    res.status(err.status).json({ error: err.message });
    return;
  }
  // eslint-disable-next-line no-console
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
}

// --- Public, no auth / no PoW ---

apiRouter.get('/pubkey', (_req, res) => {
  const { spkiB64, fingerprint } = getServerKeys();
  res.json({ spkiB64, fingerprint });
});

apiRouter.get('/pow', (req, res) => {
  const op = req.query.op as string | undefined;
  if (!op || !(op in POW_DIFFICULTY)) {
    res.status(400).json({ error: `op must be one of: ${Object.keys(POW_DIFFICULTY).join(', ')}` });
    return;
  }
  res.json(issueChallenge(op as PowOp));
});

// --- Registration & login ---

apiRouter.post('/register', requirePow('register'), async (req, res) => {
  try {
    const { username, phEnc, edPubB64 } = req.body ?? {};
    if (typeof username !== 'string' || typeof phEnc !== 'string' || typeof edPubB64 !== 'string') {
      res.status(400).json({ error: 'username, phEnc, edPubB64 are required strings' });
      return;
    }
    await registerUser(username, phEnc, edPubB64);
    res.status(201).json({ ok: true });
  } catch (err) {
    handleAuthError(err, res);
  }
});

apiRouter.post('/login/challenge', requirePow('login'), (req, res) => {
  try {
    const { username } = req.body ?? {};
    if (typeof username !== 'string') {
      res.status(400).json({ error: 'username is required' });
      return;
    }
    const salt = requestLoginSalt(username);
    res.json({ salt });
  } catch (err) {
    handleAuthError(err, res);
  }
});

apiRouter.post('/login', requirePow('login'), async (req, res) => {
  try {
    const { username, salt, proof } = req.body ?? {};
    if (typeof username !== 'string' || typeof salt !== 'string' || typeof proof !== 'string') {
      res.status(400).json({ error: 'username, salt, proof are required strings' });
      return;
    }
    const result = await verifyLogin(username, salt, proof);
    res.json(result);
  } catch (err) {
    handleAuthError(err, res);
  }
});

apiRouter.post('/logout', requireAuth, async (req, res) => {
  const header = req.header('authorization') ?? '';
  const token = header.slice('Bearer '.length);
  await logoutSession(token);
  res.json({ ok: true });
});

apiRouter.get('/users/:username/key', requireAuth, async (req, res) => {
  const target = req.params.username ?? '';
  const requester = req.username!;

  const pow: PowSubmission = {
    challenge: String(req.query.challenge ?? ''),
    nonce: String(req.query.nonce ?? ''),
  };
  if (!verifyAndBurn('userKey', pow)) {
    res.status(403).json({ error: 'Proof of work missing, invalid, or already used' });
    return;
  }

  // Self-lookup is allowed (harmless - it's your own public key), though
  // the client no longer needs it: the identity is derived from the
  // password (crypto/identity.ts::deriveIdentity), not fetched from the
  // server. Otherwise, only resolve keys for people the requester already
  // shares a room with - this is what keeps the endpoint from being a free
  // username-enumeration oracle for every registered account.
  const isSelf = target === requester;
  if (!isSelf && !(await sharesRoomWith(requester, target))) {
    res.status(404).json({ error: 'User not found' });
    return;
  }

  const edPubB64 = await getUserPublicKey(target);
  if (!edPubB64) {
    res.status(404).json({ error: 'User not found' });
    return;
  }
  res.json({ edPubB64 });
});

// --- Rooms ---

apiRouter.post('/rooms/create', requireAuth, requirePow('createRoom'), async (req, res) => {
  try {
    const { roomIdEnc, nameEnc } = req.body ?? {};
    if (typeof roomIdEnc !== 'string') {
      res.status(400).json({ error: 'roomIdEnc is required' });
      return;
    }
    const result = await createRoom(req.username!, roomIdEnc, nameEnc);
    res.status(201).json(result);
  } catch (err) {
    handleAuthError(err, res);
  }
});

apiRouter.post('/rooms/join', requireAuth, requirePow('joinRoom'), async (req, res) => {
  try {
    const { roomIdEnc } = req.body ?? {};
    if (typeof roomIdEnc !== 'string') {
      res.status(400).json({ error: 'roomIdEnc is required' });
      return;
    }
    const result = await joinRoom(req.username!, roomIdEnc);
    res.json(result);
  } catch (err) {
    handleAuthError(err, res);
  }
});

apiRouter.get('/rooms', requireAuth, async (req, res) => {
  const rooms = await listRooms(req.username!);
  res.json({ rooms });
});

apiRouter.get('/rooms/:roomId/messages', requireAuth, async (req: Request, res: Response) => {
  const { roomId } = req.params;
  const pow: PowSubmission = {
    challenge: String(req.query.challenge ?? ''),
    nonce: String(req.query.nonce ?? ''),
  };
  if (!verifyAndBurn('history', pow)) {
    res.status(403).json({ error: 'Proof of work missing, invalid, or already used' });
    return;
  }

  if (!(await isMember(req.username!, roomId!))) {
    res.status(403).json({ error: 'Not a member of this room' });
    return;
  }

  const before = req.query.before ? Number(req.query.before) : undefined;
  const limit = req.query.limit ? Number(req.query.limit) : 50;
  const docs = await getHistory(roomId!, before, limit);
  // Remap _id -> id so history messages have the same shape as the ws
  // hub's msg.new frames (see ws/hub.ts::handleSend) - the client relies on
  // a consistent `id` field across both to dedupe messages it's already
  // loaded (see client/src/ui/chat.ts).
  const messages = docs.map(({ _id, ...rest }) => ({ id: _id, ...rest }));
  res.json({ messages });
});
