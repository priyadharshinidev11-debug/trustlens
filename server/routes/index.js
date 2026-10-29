import { Router, HttpError, badRequest, unauthorized, forbidden, notFound, str } from '../lib/http.js';
import { hashPassword, verifyPassword, signJwt, verifyJwt, sha256, uuid, nowIso, newApiKey } from '../lib/auth.js';
import { scan } from '../engine/index.js';
import { CATEGORIES } from '../engine/data.js';
import { parseLoose } from '../engine/url.js';
import { isVpa } from '../engine/upi.js';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const publicUser = (u) => ({ id: u.id, name: u.name, email: u.email, role: u.role });
const parseJson = (s, fallback = null) => { try { return JSON.parse(s); } catch { return fallback; } };

export function buildRouter({ db, config, limit }) {
  const r = new Router();

  // ---------- auth helpers ----------
  async function loadUser(ctx) {
    const header = ctx.req.headers.authorization || '';
    const token = header.startsWith('Bearer ') ? header.slice(7) : null;
    const payload = token ? verifyJwt(token, config.jwtSecret) : null;
    if (!payload) return null;
    return db.get('SELECT id, email, name, role FROM users WHERE id = $1', [payload.sub]);
  }
  const optionalAuth = async (ctx) => { ctx.user = await loadUser(ctx); };
  const requireAuth = async (ctx) => { ctx.user = await loadUser(ctx); if (!ctx.user) throw unauthorized(); };
  const requireAdmin = async (ctx) => { await requireAuth(ctx); if (ctx.user.role !== 'admin') throw forbidden('Admins only'); };
  const session = (user) => ({ token: signJwt({ sub: user.id, role: user.role }, config.jwtSecret), user: publicUser(user) });

  // ---------- meta ----------
  r.get('/api/health', async () => ({ ok: true, driver: db.driver }));
  r.get('/api/meta', async () => ({ categories: CATEGORIES, blocklistThreshold: config.blocklistThreshold }));

  // ---------- auth ----------
  r.post('/api/auth/signup', async (ctx) => {
    limit(`auth:${ctx.ip}`, config.authRateLimit);
    const name = str(ctx.body.name, 'Name', { min: 2, max: 80 });
    const email = str(ctx.body.email, 'Email', { max: 200 }).toLowerCase();
    const password = str(ctx.body.password, 'Password', { min: 8, max: 200 });
    if (!EMAIL_RE.test(email)) throw badRequest('Enter a valid email address');
    if (await db.get('SELECT id FROM users WHERE email = $1', [email])) throw new HttpError(409, 'An account with this email already exists');
    const user = { id: uuid(), name, email, role: 'user' };
    const now = nowIso();
    await db.run('INSERT INTO users (id, email, name, password_hash, role, created_at, last_login_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [user.id, email, name, await hashPassword(password), 'user', now, now]);
    ctx.status = 201;
    return session(user);
  });

  r.post('/api/auth/login', async (ctx) => {
    limit(`auth:${ctx.ip}`, config.authRateLimit);
    const email = str(ctx.body.email, 'Email', { max: 200 }).toLowerCase();
    const password = str(ctx.body.password, 'Password', { max: 200 });
    const row = await db.get('SELECT * FROM users WHERE email = $1', [email]);
    // Same message for unknown email and wrong password
    if (!row || !(await verifyPassword(password, row.password_hash))) throw unauthorized('Email or password is incorrect');
    await db.run('UPDATE users SET last_login_at = $1 WHERE id = $2', [nowIso(), row.id]);
    return session(row);
  });

  r.get('/api/auth/me', requireAuth, async (ctx) => ({ user: publicUser(ctx.user) }));

  // ---------- scanning ----------
  async function runScan(input) {
    if (typeof input !== 'string' || !input.trim()) throw badRequest('Paste a link, message, UPI ID or phone number to check');
    if (input.length > 5000) throw badRequest('That is too long. Paste up to 5,000 characters');
    return scan(input, { db, config });
  }

  r.post('/api/scan', optionalAuth, async (ctx) => {
    limit(ctx.user ? `scan:${ctx.user.id}` : `scan:${ctx.ip}`, ctx.user ? 60 : 15);
    const result = await runScan(ctx.body.input);
    if (ctx.user) {
      result.id = uuid();
      result.createdAt = nowIso();
      await db.run('INSERT INTO scans (id, user_id, kind, input, verdict, score, result, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
        [result.id, ctx.user.id, result.kind, result.input.slice(0, 5000), result.verdict, result.score, JSON.stringify(result), result.createdAt]);
    }
    return result;
  });

  r.get('/api/scans', requireAuth, async (ctx) => {
    const limitN = Math.min(Number(ctx.query.get('limit')) || 20, 100);
    const offset = Math.max(Number(ctx.query.get('offset')) || 0, 0);
    const where = ['user_id = $1']; const params = [ctx.user.id];
    for (const f of ['verdict', 'kind']) {
      const v = ctx.query.get(f);
      if (v) { params.push(v); where.push(`${f} = $${params.length}`); }
    }
    const clause = where.join(' AND ');
    const items = await db.all(
      `SELECT id, kind, input, verdict, score, created_at FROM scans WHERE ${clause} ORDER BY created_at DESC LIMIT ${limitN} OFFSET ${offset}`, params);
    const total = (await db.get(`SELECT CAST(COUNT(*) AS INTEGER) AS n FROM scans WHERE ${clause}`, params)).n;
    return { items: items.map((s) => ({ ...s, input: s.input.slice(0, 160) })), total };
  });

  r.get('/api/scans/:id', requireAuth, async (ctx) => {
    const row = await db.get('SELECT id, result, created_at FROM scans WHERE id = $1 AND user_id = $2', [ctx.params.id, ctx.user.id]);
    if (!row) throw notFound('That check was not found');
    return { ...parseJson(row.result, {}), id: row.id, createdAt: row.created_at };
  });

  r.delete('/api/scans/:id', requireAuth, async (ctx) => {
    const { changes } = await db.run('DELETE FROM scans WHERE id = $1 AND user_id = $2', [ctx.params.id, ctx.user.id]);
    if (!changes) throw notFound('That check was not found');
    return { deleted: true };
  });

  r.delete('/api/scans', requireAuth, async (ctx) => {
    const { changes } = await db.run('DELETE FROM scans WHERE user_id = $1', [ctx.user.id]);
    return { deleted: changes };
  });

  // ---------- stats ----------
  r.get('/api/stats/me', requireAuth, async (ctx) => {
    const uid = ctx.user.id;
    const since = new Date(Date.now() - 13 * 864e5); since.setUTCHours(0, 0, 0, 0);
    const [byVerdict, byKind, recent] = await Promise.all([
      db.all('SELECT verdict, CAST(COUNT(*) AS INTEGER) AS n FROM scans WHERE user_id = $1 GROUP BY verdict', [uid]),
      db.all('SELECT kind, CAST(COUNT(*) AS INTEGER) AS n FROM scans WHERE user_id = $1 GROUP BY kind', [uid]),
      db.all('SELECT verdict, created_at FROM scans WHERE user_id = $1 AND created_at >= $2', [uid, since.toISOString()]),
    ]);
    const days = [];
    for (let i = 0; i < 14; i++) {
      const d = new Date(since.getTime() + i * 864e5).toISOString().slice(0, 10);
      days.push({ date: d, safe: 0, suspicious: 0, dangerous: 0, unknown: 0 });
    }
    for (const s of recent) {
      const day = days.find((d) => d.date === s.created_at.slice(0, 10));
      if (day) day[s.verdict] = (day[s.verdict] || 0) + 1;
    }
    const tally = Object.fromEntries(byVerdict.map((x) => [x.verdict, x.n]));
    return {
      total: byVerdict.reduce((a, x) => a + x.n, 0),
      verdicts: { safe: tally.safe || 0, suspicious: tally.suspicious || 0, dangerous: tally.dangerous || 0, unknown: tally.unknown || 0 },
      kinds: Object.fromEntries(byKind.map((x) => [x.kind, x.n])),
      days,
    };
  });

  r.get('/api/stats/community', async () => {
    const since = new Date(Date.now() - 30 * 864e5).toISOString();
    const [totals, trending, scans] = await Promise.all([
      db.get(`SELECT CAST(COUNT(*) AS INTEGER) AS reports,
                     CAST(COALESCE(SUM(CASE WHEN status = 'verified' THEN 1 ELSE 0 END), 0) AS INTEGER) AS verified
              FROM reports WHERE status != 'rejected'`),
      db.all(`SELECT category, CAST(COUNT(*) AS INTEGER) AS n FROM reports
              WHERE status != 'rejected' AND created_at >= $1 GROUP BY category ORDER BY n DESC LIMIT 6`, [since]),
      db.get('SELECT CAST(COUNT(*) AS INTEGER) AS n FROM scans'),
    ]);
    return { reports: totals.reports, verified: totals.verified, checks: scans.n, trending };
  });

  // ---------- community reports ----------
  function normalizeReportValue(kind, raw) {
    const v = raw.trim();
    if (kind === 'url') {
      const p = parseLoose(v);
      if (!p) throw badRequest('That does not look like a valid website address');
      return p.url.hostname.toLowerCase().replace(/^www\./, '');
    }
    if (kind === 'upi') {
      if (!isVpa(v)) throw badRequest('A UPI ID looks like name@bank');
      return v.toLowerCase();
    }
    if (kind === 'phone') {
      const digits = v.replace(/\D/g, '');
      if (digits.length < 8 || digits.length > 15) throw badRequest('Enter a phone number with 8 to 15 digits');
      return v.startsWith('+') ? `+${digits}` : digits.length === 10 ? `+91${digits}` : `+${digits}`;
    }
    return v.replace(/\s+/g, ' ').slice(0, 300);
  }

  const reportRow = (x, myVote = 0) => ({
    id: x.id, kind: x.kind, value: x.value, category: x.category, description: x.description, status: x.status,
    confirms: x.confirms, disputes: x.disputes, createdAt: x.created_at, myVote,
  });

  r.get('/api/reports', optionalAuth, async (ctx) => {
    const limitN = Math.min(Number(ctx.query.get('limit')) || 30, 100);
    const where = [`r.status != 'rejected'`]; const params = [];
    const kind = ctx.query.get('kind'); const status = ctx.query.get('status'); const q = ctx.query.get('q');
    if (kind) { params.push(kind); where.push(`r.kind = $${params.length}`); }
    if (status === 'verified' || status === 'pending') { params.push(status); where.push(`r.status = $${params.length}`); }
    if (q) { params.push(`%${q.toLowerCase().slice(0, 100)}%`); where.push(`LOWER(r.value) LIKE $${params.length}`); }
    const order = ctx.query.get('sort') === 'top' ? 'r.confirms - r.disputes DESC, r.created_at DESC' : 'r.created_at DESC';
    const rows = await db.all(`SELECT r.* FROM reports r WHERE ${where.join(' AND ')} ORDER BY ${order} LIMIT ${limitN}`, params);
    let votes = {};
    if (ctx.user && rows.length) {
      const mine = await db.all('SELECT report_id, vote FROM report_votes WHERE user_id = $1', [ctx.user.id]);
      votes = Object.fromEntries(mine.map((v) => [v.report_id, v.vote]));
    }
    return { items: rows.map((x) => reportRow(x, votes[x.id] || 0)) };
  });

  async function recount(reportId) {
    await db.run(
      `UPDATE reports SET
         confirms = (SELECT CAST(COUNT(*) AS INTEGER) FROM report_votes WHERE report_id = $1 AND vote = 1),
         disputes = (SELECT CAST(COUNT(*) AS INTEGER) FROM report_votes WHERE report_id = $1 AND vote = -1),
         updated_at = $2
       WHERE id = $1`, [reportId, nowIso()]);
    return db.get('SELECT * FROM reports WHERE id = $1', [reportId]);
  }
  const castVote = (reportId, userId, vote) => db.run(
    `INSERT INTO report_votes (report_id, user_id, vote, created_at) VALUES ($1,$2,$3,$4)
     ON CONFLICT (report_id, user_id) DO UPDATE SET vote = excluded.vote`, [reportId, userId, vote, nowIso()]);

  r.post('/api/reports', requireAuth, async (ctx) => {
    limit(`report:${ctx.user.id}`, 10, 10 * 60_000);
    const kind = str(ctx.body.kind, 'Type');
    if (!['url', 'upi', 'phone', 'message'].includes(kind)) throw badRequest('Choose a valid report type');
    const category = str(ctx.body.category, 'Category');
    if (!CATEGORIES.includes(category)) throw badRequest('Choose a valid category');
    const value = normalizeReportValue(kind, str(ctx.body.value, 'What are you reporting?', { max: 2000 }));
    const description = str(ctx.body.description, 'Description', { optional: true, max: 600 });

    const existing = await db.get(`SELECT * FROM reports WHERE kind = $1 AND value = $2 AND status != 'rejected'`, [kind, value]);
    if (existing) {
      await castVote(existing.id, ctx.user.id, 1);
      return { ...reportRow(await recount(existing.id), 1), merged: true };
    }
    const id = uuid(); const now = nowIso();
    await db.run('INSERT INTO reports (id, user_id, kind, value, category, description, status, confirms, disputes, created_at, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
      [id, ctx.user.id, kind, value, category, description || null, 'pending', 0, 0, now, now]);
    await castVote(id, ctx.user.id, 1);
    ctx.status = 201;
    return { ...reportRow(await recount(id), 1), merged: false };
  });

  r.post('/api/reports/:id/vote', requireAuth, async (ctx) => {
    limit(`vote:${ctx.user.id}`, 60);
    const vote = Number(ctx.body.vote);
    if (![1, -1, 0].includes(vote)) throw badRequest('Vote must be 1, -1 or 0');
    const rep = await db.get('SELECT id FROM reports WHERE id = $1', [ctx.params.id]);
    if (!rep) throw notFound('Report not found');
    if (vote === 0) await db.run('DELETE FROM report_votes WHERE report_id = $1 AND user_id = $2', [rep.id, ctx.user.id]);
    else await castVote(rep.id, ctx.user.id, vote);
    return reportRow(await recount(rep.id), vote);
  });

  // ---------- admin ----------
  r.get('/api/admin/overview', requireAdmin, async () => {
    const n = async (sql, p = []) => (await db.get(sql, p)).n;
    return {
      users: await n('SELECT CAST(COUNT(*) AS INTEGER) AS n FROM users'),
      scans: await n('SELECT CAST(COUNT(*) AS INTEGER) AS n FROM scans'),
      reportsPending: await n(`SELECT CAST(COUNT(*) AS INTEGER) AS n FROM reports WHERE status = 'pending'`),
      reportsVerified: await n(`SELECT CAST(COUNT(*) AS INTEGER) AS n FROM reports WHERE status = 'verified'`),
      reportsRejected: await n(`SELECT CAST(COUNT(*) AS INTEGER) AS n FROM reports WHERE status = 'rejected'`),
    };
  });

  r.get('/api/admin/reports', requireAdmin, async (ctx) => {
    const status = ['pending', 'verified', 'rejected'].includes(ctx.query.get('status')) ? ctx.query.get('status') : 'pending';
    const rows = await db.all(
      `SELECT r.*, u.email AS reporter FROM reports r LEFT JOIN users u ON u.id = r.user_id
       WHERE r.status = $1 ORDER BY r.confirms - r.disputes DESC, r.created_at DESC LIMIT 100`, [status]);
    return { items: rows.map((x) => ({ ...reportRow(x), reporter: x.reporter })) };
  });

  r.post('/api/admin/reports/:id/status', requireAdmin, async (ctx) => {
    const status = str(ctx.body.status, 'Status');
    if (!['pending', 'verified', 'rejected'].includes(status)) throw badRequest('Invalid status');
    const { changes } = await db.run('UPDATE reports SET status = $1, updated_at = $2 WHERE id = $3', [status, nowIso(), ctx.params.id]);
    if (!changes) throw notFound('Report not found');
    return reportRow(await db.get('SELECT * FROM reports WHERE id = $1', [ctx.params.id]));
  });

  // ---------- API keys ----------
  r.get('/api/keys', requireAuth, async (ctx) => {
    const rows = await db.all('SELECT id, name, prefix, created_at, last_used_at FROM api_keys WHERE user_id = $1 AND revoked = 0 ORDER BY created_at DESC', [ctx.user.id]);
    return { items: rows.map((k) => ({ id: k.id, name: k.name, prefix: k.prefix, createdAt: k.created_at, lastUsedAt: k.last_used_at })) };
  });

  r.post('/api/keys', requireAuth, async (ctx) => {
    const name = str(ctx.body.name, 'Key name', { max: 60 });
    const count = (await db.get('SELECT CAST(COUNT(*) AS INTEGER) AS n FROM api_keys WHERE user_id = $1 AND revoked = 0', [ctx.user.id])).n;
    if (count >= 5) throw badRequest('You can have up to 5 active keys. Revoke one first.');
    const k = newApiKey(); const id = uuid();
    await db.run('INSERT INTO api_keys (id, user_id, name, prefix, key_hash, created_at, revoked) VALUES ($1,$2,$3,$4,$5,$6,0)', [id, ctx.user.id, name, k.prefix, k.hash, nowIso()]);
    ctx.status = 201;
    return { id, name, prefix: k.prefix, key: k.key, note: 'Copy this key now. It will not be shown again.' };
  });

  r.delete('/api/keys/:id', requireAuth, async (ctx) => {
    const { changes } = await db.run('UPDATE api_keys SET revoked = 1 WHERE id = $1 AND user_id = $2', [ctx.params.id, ctx.user.id]);
    if (!changes) throw notFound('Key not found');
    return { revoked: true };
  });

  // ---------- public API (API key) ----------
  r.post('/api/v1/scan', async (ctx) => {
    const key = ctx.req.headers['x-api-key'];
    if (!key) throw unauthorized('Send your key in the X-API-Key header');
    const row = await db.get('SELECT id FROM api_keys WHERE key_hash = $1 AND revoked = 0', [sha256(String(key))]);
    if (!row) throw unauthorized('That API key is not valid');
    limit(`key:${row.id}`, 120);
    await db.run('UPDATE api_keys SET last_used_at = $1 WHERE id = $2', [nowIso(), row.id]);
    const result = await runScan(ctx.body.input);
    return { kind: result.kind, verdict: result.verdict, score: result.score, summary: result.summary, category: result.category,
      signals: result.signals.map(({ id, label, detail, weight }) => ({ id, label, detail, weight })), advice: result.advice };
  });

  return r;
}
