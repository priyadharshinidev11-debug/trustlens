import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../server/app.js';
import { config } from '../server/config.js';

let server, base;
const cfg = { ...config, sqlitePath: ':memory:', databaseUrl: '', adminEmail: 'admin@test.dev', adminPassword: 'Password123!', blocklistThreshold: 3, authRateLimit: 1000 };

before(async () => {
  ({ server } = await createApp(cfg));
  await new Promise((r) => server.listen(0, r));
  base = `http://localhost:${server.address().port}`;
});
after(() => server.close());

async function call(method, path, body, token, headers = {}) {
  const res = await fetch(base + path, { method, headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}), ...headers }, body: body ? JSON.stringify(body) : undefined });
  return { status: res.status, body: await res.json().catch(() => ({})) };
}
const signup = async (n) => (await call('POST', '/api/auth/signup', { name: `User ${n}`, email: `u${n}@test.dev`, password: 'longpassword' })).body.token;

test('auth: signup, duplicate, bad login, me', async () => {
  const t = await signup(1);
  assert.ok(t);
  assert.equal((await call('POST', '/api/auth/signup', { name: 'Dup', email: 'u1@test.dev', password: 'longpassword' })).status, 409);
  assert.equal((await call('POST', '/api/auth/login', { email: 'u1@test.dev', password: 'nope-nope' })).status, 401);
  assert.equal((await call('GET', '/api/auth/me', null, t)).body.user.email, 'u1@test.dev');
  assert.equal((await call('GET', '/api/auth/me')).status, 401);
});

test('scan: guests are not saved, members are', async () => {
  const guest = await call('POST', '/api/scan', { input: 'http://sbi-kyc-update.xyz/login' });
  assert.equal(guest.body.verdict, 'dangerous');
  assert.equal(guest.body.id, undefined);
  const t = await signup(2);
  const mine = await call('POST', '/api/scan', { input: 'http://sbi-kyc-update.xyz/login' }, t);
  assert.ok(mine.body.id);
  assert.equal((await call('GET', '/api/scans', null, t)).body.total, 1);
  assert.equal((await call('POST', '/api/scan', { input: '   ' })).status, 400);
});

test('users cannot read or delete each other\'s scans', async () => {
  const a = await signup(3), b = await signup(4);
  const { body } = await call('POST', '/api/scan', { input: 'hello there' }, a);
  assert.equal((await call('GET', `/api/scans/${body.id}`, null, b)).status, 404);
  assert.equal((await call('DELETE', `/api/scans/${body.id}`, null, b)).status, 404);
});

test('community: reports merge, votes build a blocklist, admin can reject', async () => {
  const tokens = [];
  for (let i = 10; i < 14; i++) tokens.push(await signup(i));
  const rep = await call('POST', '/api/reports', { kind: 'url', value: 'https://totally-fake-bank.example.top/x', category: 'Phishing link' }, tokens[0]);
  assert.equal(rep.status, 201);
  const dup = await call('POST', '/api/reports', { kind: 'url', value: 'totally-fake-bank.example.top', category: 'Phishing link' }, tokens[1]);
  assert.equal(dup.body.merged, true);
  assert.equal((await call('POST', '/api/scan', { input: 'totally-fake-bank.example.top' })).body.community.length, 0);
  await call('POST', `/api/reports/${rep.body.id}/vote`, { vote: 1 }, tokens[2]);
  const after = await call('POST', '/api/scan', { input: 'totally-fake-bank.example.top' });
  assert.equal(after.body.community.length, 1);
  assert.ok(after.body.signals.some((s) => s.id === 'community_report'));

  assert.equal((await call('GET', '/api/admin/reports', null, tokens[0])).status, 403);
  const admin = (await call('POST', '/api/auth/login', { email: 'admin@test.dev', password: 'Password123!' })).body.token;
  await call('POST', `/api/admin/reports/${rep.body.id}/status`, { status: 'rejected' }, admin);
  assert.equal((await call('POST', '/api/scan', { input: 'totally-fake-bank.example.top' })).body.community.length, 0);
});

test('api keys: create, use, revoke', async () => {
  const t = await signup(20);
  const k = await call('POST', '/api/keys', { name: 'bot' }, t);
  assert.ok(k.body.key.startsWith('tl_live_'));
  const ok = await call('POST', '/api/v1/scan', { input: 'rahul@oksbi' }, null, { 'X-API-Key': k.body.key });
  assert.equal(ok.body.verdict, 'safe');
  assert.equal((await call('POST', '/api/v1/scan', { input: 'x.com' }, null, { 'X-API-Key': 'bad' })).status, 401);
  await call('DELETE', `/api/keys/${k.body.id}`, null, t);
  assert.equal((await call('POST', '/api/v1/scan', { input: 'x.com' }, null, { 'X-API-Key': k.body.key })).status, 401);
});

test('static files are served and path traversal is blocked', async () => {
  assert.equal((await fetch(base + '/')).status, 200);
  assert.equal((await fetch(base + '/css/app.css')).status, 200);
  assert.equal((await fetch(base + '/..%2fserver%2fconfig.js')).status, 404);
});
