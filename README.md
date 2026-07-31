# SecureCord

A small, self-hosted, end-to-end-encrypted group chat. A `client/` (esbuild +
TypeScript, no framework) talks to a `server/` (Express + `ws`, MongoDB) over
REST and WebSocket. The server is built to see as little as possible: it
brokers RSA-wrapped key material, stores AES-GCM ciphertext it cannot
decrypt, and rejects anything that isn't validly signed - but it is not
zero-trust. Read the [Threat model](#threat-model--limitations) section
before treating this as a security boundary for anything that matters.

## Running it

```bash
docker compose up --build
```

This starts two containers on an internal-only Docker network:

- **`mongo`** - no auth, no published port. It is reachable only from the
  `server` container, by the Compose DNS name `mongo`. It is never reachable
  from the host (`nc -vz localhost 27017` will fail).
- **`server`** - Express + `ws` on `:8080` (published to the host), serving
  the built client from `client/dist` and the REST/WS API from the same
  origin. On first boot it generates a 4096-bit RSA keypair under
  `server/data/keys/` (bind-mounted, so it survives rebuilds).

Before the first `up`, build the client once (the server serves whatever is
in `client/dist`):

```bash
cd client && npm install && npm run build
```

For local development, `npm run dev` in `client/` runs an esbuild `--watch`
loop; the server container runs `tsx watch` against a bind-mounted
`server/src`, so both sides live-reload.

## How a message actually gets from A to B

1. **Room codes never leave the browser.** `H1 = sha256(code)` is the
   AES-256 key. `H2 = sha256(H1)` is the only thing that goes to the server
   (RSA-OAEP-wrapped under the server's public key), and it's what the
   server uses as the room's `_id`. The room's display name is itself
   AES-encrypted under `H1` before it's sent, so a database read reveals
   neither the code nor the name.
2. **Passwords never leave the browser either**, in a weaker but related
   sense: `PH = sha256(password)` is sent once at registration
   (RSA-wrapped). Every login after that is challenge-response: the server
   hands out a single-use `salt`, and the client sends
   `proof = sha256(PH + salt)` - the password and `PH` are never transmitted
   again.
3. **Every message is Ed25519-signed** over the canonical string
   `roomId|sender|ts|iv|ct`, where `iv`/`ct` are the AES-GCM nonce and
   ciphertext. The server verifies this against the sender's registered
   public key and refuses to store or broadcast anything unsigned or
   invalidly signed. It also never sees the plaintext: it only ever holds
   `iv` and `ct`. A message's `_id` is `sha256(canonical)` rather than a
   random UUID, so resubmitting an old, already-stored signed frame
   verbatim - a signature proves authorship, not freshness - collides on
   insert instead of quietly becoming a duplicate; a claimed timestamp more
   than 5 minutes from the server's clock is rejected outright (see
   `server/src/messages.ts`).
4. **Proof-of-work gates every write-ish endpoint** (register, login,
   create/join room, send message, fetch history, user-key lookup) with an
   escalating-difficulty sha256 puzzle - the server hands out a
   self-describing, HMAC-authenticated challenge (nothing is stored until
   it's actually solved, so issuing challenges for free costs an attacker's
   memory nothing), the client counts up in hex appending the counter as a
   string until the digest ends in `difficulty` zero hex digits, and each
   solved challenge is burned after one use (see `server/src/pow.ts`). PoW
   makes each request cost something (anti-*bot*); it deliberately isn't
   expensive enough at interactive difficulties to bound sustained *volume*
   from an already-authenticated account, so a token-bucket rate limit sits
   alongside it for that (15-message burst / 5 sustained per second on
   sending - see `server/src/ratelimit.ts`).

## Threat model & limitations

This is deliberately honest about what it does *not* protect against:

1. **A malicious server can forge messages by substituting keys.** The
   server is the one who hands out Ed25519 public keys (`GET
   /api/users/:username/key`). A curious-but-passive server can't decrypt
   anything and can't forge a valid signature, but an actively malicious
   server could serve an attacker's public key in place of a real user's
   and then forge messages that verify. The client mitigates this with
   **trust-on-first-use pinning**: the first public key ever seen for a
   username is cached locally (IndexedDB), and every later sighting is
   compared against that pin rather than trusted again. A mismatch is
   surfaced as an "invalid signature" on the message and a console warning,
   never silently accepted - see `client/src/store/vault.ts::checkAndPinPeer`
   and `client/src/ui/chat.ts::getSignerKey`. This defeats an attack that
   starts after the first legitimate contact; it does not defeat a server
   that's malicious from that very first sighting. There is no
   out-of-band identity verification UI (e.g. comparing fingerprints over a
   different channel) beyond showing the fingerprint in the sidebar.
2. **The server stores your password hash, not just its challenge-response
   trace.** To verify `proof = sha256(PH + salt)` at login, the server must
   keep `PH = sha256(password)` around. That means a database compromise
   yields a password-equivalent value per user (an attacker who reads `PH`
   can compute valid login proofs without ever knowing the real password).
   This is inherent to any simple shared-secret challenge-response scheme;
   avoiding it needs an asymmetric protocol like SRP or OPAQUE, which is out
   of scope here. The one thing this design does get right is that `PH`
   itself is never sent over the wire in the clear after registration (it's
   RSA-wrapped once, at signup) and the raw password is never sent at all
   after that point.

Other things worth knowing:

- **Metadata is not hidden.** `sender`, `roomId`, and both a client-claimed
  and a server-observed timestamp are stored and forwarded in the clear
  alongside the ciphertext. Only the message *content* (via AES-GCM) and
  the room *name and code* (via the H1/H2 scheme above) are hidden from the
  server.
- **PoW state and login salts are in-memory,** not persisted (see
  `server/src/pow.ts`, `server/src/auth.ts`). A server restart simply
  invalidates outstanding challenges - clients transparently re-request one
  - but this does not scale past a single server instance.
- **The Ed25519 identity is local-only and per-browser-profile.** It's
  generated on first load and stored in IndexedDB; nothing about it is ever
  transmitted except the public key at registration. If you log into the
  same account from a new browser/device without importing the original
  identity backup (sidebar → Export, then Import on the new device), that
  new browser gets a *different* keypair than the one already registered
  for the account, and every message it signs will be **rejected by the
  server** as invalid until you import the correct backup. The app detects
  this (comparing the login response's registered key against the local
  one) and shows a banner rather than failing silently.
- **Room membership is a wrong-code oracle otherwise, so it's deliberately
  vague.** `POST /api/rooms/join` returns an identical 404 for "no room
  with this code" and "this room doesn't exist at all" - if it distinguished
  the two, an attacker could use the response to check candidate codes
  against known rooms.
- **`GET /api/users/:username/key` only resolves people you already share a
  room with** (or your own key). Otherwise a single account would let
  anyone enumerate the full set of registered usernames at network speed -
  see `server/src/rooms.ts::sharesRoomWith`. Every legitimate lookup in the
  app (verifying a message's sender) is already scoped to a room you're
  subscribed to, so this doesn't restrict normal use.

## Layout

```
client/           esbuild + TypeScript, no framework
  src/crypto/     sha256, RSA-OAEP, AES-GCM, Ed25519, PoW solver
  src/net/        REST client, WebSocket client
  src/store/      IndexedDB vault (identity, room keys, pinned peer keys, session)
  src/ui/         screen controllers (auth, rooms, chat)
server/           Express + ws + MongoDB
  src/keys.ts       RSA keypair, generated on first boot, persisted to server/data/keys
  src/pow.ts        stateless HMAC-authenticated proof-of-work challenges
  src/ratelimit.ts  per-key token-bucket rate limiting (the anti-flood layer PoW isn't)
  src/auth.ts       register + challenge-response login
  src/rooms.ts      room create/join/list, sharesRoomWith()
  src/messages.ts   signature verification + persistence + replay rejection
  src/mongoErrors.ts shared Mongo duplicate-key detection
  src/ws/hub.ts     WebSocket fan-out
docker-compose.yml
```
