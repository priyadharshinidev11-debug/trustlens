import http from 'node:http';
import { createDb, migrate } from './db/index.js';
import { buildRouter } from './routes/index.js';
import { HttpError, readJson, sendJson, serveStatic, createLimiter, SECURITY_HEADERS } from './lib/http.js';
import { hashPassword, uuid, nowIso } from './lib/auth.js';

/** Builds the HTTP server. Exported separately from index.js so tests can start it on a random port. */
export async function createApp(config, existingDb) {
  const db = existingDb || await createDb(config);
  await migrate(db);
  await ensureAdmin(db, config);

  const limit = createLimiter();
  const router = buildRouter({ db, config, limit });

  const clientIp = (req) => {
    if (config.trustProxy) {
      const xff = req.headers['x-forwarded-for'];
      if (xff) return String(xff).split(',')[0].trim();
    }
    return req.socket.remoteAddress || 'unknown';
  };

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, 'http://localhost');
    if (!url.pathname.startsWith('/api/')) {
      if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
      return serveStatic(config.webDir, url.pathname, res);
    }

    const cors = url.pathname.startsWith('/api/v1/')
      ? { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, X-API-Key', 'Access-Control-Allow-Methods': 'POST, OPTIONS' }
      : {};
    if (req.method === 'OPTIONS') { res.writeHead(204, cors); return res.end(); }

    try {
      const ip = clientIp(req);
      limit(`ip:${ip}`, 300);
      const route = router.match(req.method, url.pathname);
      if (!route) throw new HttpError(404, 'Unknown endpoint');
      const ctx = { req, res, url, query: url.searchParams, params: route.params, ip, status: 200, user: null, body: {} };
      if (['POST', 'PUT', 'PATCH'].includes(req.method)) ctx.body = await readJson(req);

      let out;
      for (const handler of route.handlers) {
        const value = await handler(ctx);
        if (value !== undefined) out = value;
      }
      sendJson(res, ctx.status, out ?? { ok: true }, { ...cors, ...pick(SECURITY_HEADERS, ['X-Content-Type-Options']) });
    } catch (err) {
      if (err instanceof HttpError) return sendJson(res, err.status, { error: err.message, details: err.details }, cors);
      console.error('Unhandled error:', err);
      sendJson(res, 500, { error: 'Something went wrong on our side. Please try again.' }, cors);
    }
  });

  server.on('close', () => { db.close().catch(() => {}); });
  return { server, db };
}

const pick = (o, keys) => Object.fromEntries(keys.map((k) => [k, o[k]]));

async function ensureAdmin(db, config) {
  if (!config.adminEmail || !config.adminPassword) return;
  const email = config.adminEmail.toLowerCase();
  const existing = await db.get('SELECT id, role FROM users WHERE email = $1', [email]);
  if (existing) {
    if (existing.role !== 'admin') await db.run(`UPDATE users SET role = 'admin' WHERE id = $1`, [existing.id]);
    return;
  }
  await db.run('INSERT INTO users (id, email, name, password_hash, role, created_at) VALUES ($1,$2,$3,$4,$5,$6)',
    [uuid(), email, 'Administrator', await hashPassword(config.adminPassword), 'admin', nowIso()]);
  console.log(`Created admin account ${email}`);
}
