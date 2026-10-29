import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

// Tiny .env loader (no dependency). Real environment variables always win.
const envFile = path.join(root, '.env');
if (fs.existsSync(envFile)) {
  for (const line of fs.readFileSync(envFile, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
}

const isProd = process.env.NODE_ENV === 'production';
const env = (k, d = '') => (process.env[k] === undefined || process.env[k] === '' ? d : process.env[k]);

if (isProd && !env('JWT_SECRET')) {
  console.error('FATAL: JWT_SECRET must be set when NODE_ENV=production');
  process.exit(1);
}

export const config = {
  root,
  isProd,
  port: Number(env('PORT', 3000)),
  jwtSecret: env('JWT_SECRET', 'dev-only-secret-change-me'),
  trustProxy: env('TRUST_PROXY', '0') === '1',
  databaseUrl: env('DATABASE_URL'),
  sqlitePath: env('SQLITE_PATH', path.join(root, 'data', 'trustlens.db')),
  adminEmail: env('ADMIN_EMAIL'),
  adminPassword: env('ADMIN_PASSWORD'),
  safeBrowsingKey: env('GOOGLE_SAFE_BROWSING_KEY'),
  blocklistThreshold: Number(env('BLOCKLIST_THRESHOLD', 3)),
  authRateLimit: Number(env('AUTH_RATE_LIMIT', 10)), // signup + login attempts per IP per minute
  webDir: path.join(root, 'web'),
};
