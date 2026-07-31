import path from 'node:path';

export const PORT = Number(process.env.PORT ?? 8080);
export const MONGO_URL = process.env.MONGO_URL ?? 'mongodb://mongo:27017/securecord';

// /app/data in the container (bind-mounted to ./server/data on the host so
// the RSA keypair survives image rebuilds and restarts).
export const DATA_DIR = process.env.DATA_DIR ?? path.resolve(process.cwd(), 'data');
export const KEYS_DIR = path.join(DATA_DIR, 'keys');

// Static client bundle (client/dist, bind-mounted read-only).
export const PUBLIC_DIR = process.env.PUBLIC_DIR ?? path.resolve(process.cwd(), 'public');

export const SESSION_TTL_MS = 24 * 60 * 60 * 1000; // 24h
export const LOGIN_SALT_TTL_MS = 60 * 1000; // 60s, single-use
export const POW_TTL_MS = 5 * 60 * 1000; // 5 min
