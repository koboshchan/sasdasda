import http from 'node:http';
import path from 'node:path';
import express from 'express';
import { PORT, PUBLIC_DIR } from './config.js';
import { getServerKeys } from './keys.js';
import { connectDb } from './db.js';
import { apiRouter } from './routes/api.js';
import { attachWsHub } from './ws/hub.js';

async function main(): Promise<void> {
  // Generate the RSA keypair on first boot (or load it if it already
  // exists) before accepting any traffic - registration, login and room
  // creation all depend on it.
  const keys = getServerKeys();
  console.log(`RSA keypair ready. Public key fingerprint: ${keys.fingerprint}`);

  await connectDb();
  console.log('Connected to MongoDB.');

  const app = express();
  app.use(express.json({ limit: '256kb' }));
  app.use('/api', apiRouter);
  app.use(express.static(PUBLIC_DIR));
  // SPA fallback: any non-/api route serves index.html.
  app.get(/^(?!\/api).*/, (_req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
  });

  const server = http.createServer(app);
  attachWsHub(server);

  server.listen(PORT, () => {
    console.log(`Mango server listening on :${PORT}`);
  });
}

main().catch((err) => {
  console.error('Fatal startup error:', err);
  process.exit(1);
});
