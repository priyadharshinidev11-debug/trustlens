import crypto from 'node:crypto';
import { promisify } from 'node:util';

const scrypt = promisify(crypto.scrypt);
const b64u = (buf) => Buffer.from(buf).toString('base64url');

export async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(password, salt, 64);
  return `scrypt$${salt.toString('base64')}$${key.toString('base64')}`;
}

export async function verifyPassword(password, stored) {
  const [scheme, saltB64, keyB64] = String(stored).split('$');
  if (scheme !== 'scrypt' || !saltB64 || !keyB64) return false;
  const expected = Buffer.from(keyB64, 'base64');
  const actual = await scrypt(password, Buffer.from(saltB64, 'base64'), expected.length);
  return crypto.timingSafeEqual(actual, expected);
}

// Minimal HS256 JWT
export function signJwt(payload, secret, ttlSeconds = 60 * 60 * 24 * 7) {
  const header = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64u(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + ttlSeconds }));
  const sig = crypto.createHmac('sha256', secret).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

export function verifyJwt(token, secret) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  const expected = crypto.createHmac('sha256', secret).update(`${parts[0]}.${parts[1]}`).digest();
  const given = Buffer.from(parts[2], 'base64url');
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    return payload.exp > Date.now() / 1000 ? payload : null;
  } catch {
    return null;
  }
}

export const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
export const uuid = () => crypto.randomUUID();
export const nowIso = () => new Date().toISOString();
export function newApiKey() {
  const secret = crypto.randomBytes(24).toString('base64url');
  const key = `tl_live_${secret}`;
  return { key, prefix: key.slice(0, 12), hash: sha256(key) };
}
