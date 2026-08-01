# Mango

A small, self-hosted, end-to-end-encrypted group chat. A `client/` (esbuild +
TypeScript, no framework) talks to a `server/` (Express + `ws`, MongoDB) over
REST and WebSocket. The server is built to see as little as possible: it
brokers RSA-wrapped key material, stores AES-GCM ciphertext it cannot
decrypt, and rejects anything that isn't validly signed - but it is not
zero-trust. Read the [Threat model](#threat-model--limitations) section
before treating this as a security boundary for anything that matters.

## Running it

Production deployment is at `https://mango.kjt.lol`, served by whatever reverse
proxy/TLS terminator sits in front of the `server` container's `:8080` -
that's outside this repo. Nothing in the app hardcodes an origin (the
client talks to `fetch()`-relative paths and `location.host` for the
WebSocket URL - see `client/src/net/ws.ts`), so the same image runs
correctly under any hostname it's served from, local or not.

```bash
docker compose up --build
```

That's the whole setup - there is no separate client build step. This
builds a prod image (see the root `Dockerfile`: a `client-builder` stage
bundles `client/` with esbuild, a `server-builder` stage bundles `server/`
into a single dependency-free `dist/server.cjs` with esbuild, and a `runner`
stage ships only those two build outputs - no TypeScript source, no
`node_modules`, no `npx`/`tsx` in the running container) and starts two
containers on an internal-only Docker network:

- **`mongo`** - no auth, no published port. It is reachable only from the
  `server` container, by the Compose DNS name `mongo`. It is never reachable
  from the host (`nc -vz localhost 27017` will fail).
- **`server`** - Express + `ws` on `:8080` (published to the host), serving
  the bundled client and the REST/WS API from the same origin. On first
  boot it generates a 4096-bit RSA keypair under `server/data/keys/`
  (bind-mounted - the only volume left, since the client bundle and server
  code are now baked into the image - so the keypair survives rebuilds).

For local development instead of the prod image, `npm run dev` in
`client/` runs an esbuild `--watch` loop, and `npm run dev` in `server/`
runs `tsx watch` directly against the TypeScript source.

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
3. **The Ed25519 signing identity is derived from the same password**,
   not generated randomly: `seed = sha256("sc-ed25519-v1|" + password)` is
   the Ed25519 secret key (see `client/src/crypto/identity.ts::deriveIdentity`).
   This is deliberately *not* derived from `PH` - the server stores `PH`, so
   seeding from it would let a compromised server derive every user's
   private signing key straight out of its own database. Seeding from the
   raw password instead (which the server never sees) means the same
   account produces the identical keypair on any device from the password
   alone - there's no export/import step, and nothing at all to synchronize
   between devices.
4. **Every message is Ed25519-signed** over the canonical string
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
5. **Proof-of-work is the only admission control**, not just an anti-bot
   speed bump alongside a rate limit - every write-ish endpoint (register,
   login, create/join room, send message, fetch history, user-key lookup)
   requires an escalating-difficulty sha256 puzzle, and a solved challenge
   is treated as sufficient approval on its own. The server hands out a
   self-describing, HMAC-authenticated challenge (nothing is stored until
   it's actually solved, so issuing challenges for free costs an attacker's
   memory nothing), the client counts up in hex appending the counter as a
   string until the digest ends in `difficulty` zero hex digits, and each
   solved challenge is burned after one use (see `server/src/pow.ts`).
   There is deliberately no separate token-bucket/volume limiter on top of
   this - see the threat model below for what that trades away.

## Message history & rendering

Opening a room fetches the newest 100 messages; scrolling toward the top of
the visible history requests 100 more (via `GET
/api/rooms/:roomId/messages?before=...`, still gated by its own PoW
challenge), and scrolling back down re-reveals previously-loaded messages
from memory rather than re-fetching them. The DOM never holds more than 500
rendered messages at once - crossing that ceiling trims back down to 400,
discarding whichever end (oldest or newest) is furthest from the current
scroll position. Verifying a signature and decrypting a message both happen
at most once per message, cached for as long as it stays in memory, even as
it's repeatedly trimmed from and re-added to the DOM (see
`client/src/ui/chat.ts`).

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
   different channel) beyond showing the fingerprint in the sidebar. This
   risk is specifically about *other people's* keys - your own signing key
   is never fetched from the server at all (see point 3 below), so there's
   nothing for the server to substitute there.
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
   after that point. Critically, `PH` is *not* what the Ed25519 signing key
   is derived from (see point 3) - a `PH` leak lets an attacker log in as
   you, but does not by itself let them forge your signature.
3. **The Ed25519 identity is derived from the password, not stored
   server-side or exported between devices.** Logging into the same account
   from a new browser/device reproduces the identical keypair from the
   password alone (see "How a message actually gets from A to B" above) -
   there is no backup file to lose, and no "wrong keypair on this device"
   state is reachable for an account logging in with its correct password.
   The corollary is that **the password is now doing double duty as both
   the login secret and the signing key seed**: anyone who obtains the
   password can both log in *and* forge that user's future signatures
   (whereas a leaked `PH` alone cannot). This is why the two are derived
   with different domain-separated hashes rather than one being reused for
   the other, even though that doesn't change the fact that both trace back
   to the same underlying secret. A locally-persisted copy of the derived
   seed (so a page reload doesn't need the password retyped) is deleted on
   logout - see `client/src/store/vault.ts::deleteIdentitySeed` and
   `client/src/main.ts::handleLogout`.
4. **There is no rate limiting - a solved proof-of-work is the only
   thing standing between an authenticated account and unlimited request
   volume.** PoW difficulty is tuned low on `sendMessage` (and similarly
   cheap ops) so legitimate use doesn't feel throttled, which means a
   scripted client that keeps solving challenges can sustain a high message
   rate from one account - PoW bounds cost-per-request (anti-*bot*), not
   sustained *volume* (anti-flood), and this app deliberately does not
   layer a separate volume cap on top of it. If you need to bound sustained
   throughput from a single already-authenticated account, that's a gap to
   close before relying on this for anything at scale.

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
- **Room membership is a wrong-code oracle otherwise, so it's deliberately
  vague.** `POST /api/rooms/join` returns an identical 404 for "no room
  with this code" and "this room doesn't exist at all" - if it distinguished
  the two, an attacker could use the response to check candidate codes
  against known rooms.
- **`GET /api/users/:username/key` only resolves people you already share a
  room with** (self-lookup is also allowed, though the client no longer
  needs it - see point 3 above). Otherwise a single account would let
  anyone enumerate the full set of registered usernames at network speed -
  see `server/src/rooms.ts::sharesRoomWith`. Every legitimate lookup in the
  app (verifying a message's sender) is already scoped to a room you're
  subscribed to, so this doesn't restrict normal use.

## Layout

```
Dockerfile        multi-stage prod build: client-builder / server-builder / runner
docker-compose.yml
client/           esbuild + TypeScript, no framework
  src/crypto/     sha256, RSA-OAEP, AES-GCM, password-derived Ed25519, PoW solver
  src/net/        REST client, WebSocket client
  src/store/      IndexedDB vault (per-account identity seed, room keys, pinned peer keys, session)
  src/ui/         screen controllers (auth, rooms, chat - windowed message rendering)
server/           Express + ws + MongoDB
  src/keys.ts       RSA keypair, generated on first boot, persisted to server/data/keys
  src/pow.ts        stateless HMAC-authenticated proof-of-work challenges
  src/auth.ts       register + challenge-response login
  src/rooms.ts      room create/join/list, sharesRoomWith()
  src/messages.ts   signature verification + persistence + replay rejection
  src/mongoErrors.ts shared Mongo duplicate-key detection
  src/ws/hub.ts     WebSocket fan-out
```
