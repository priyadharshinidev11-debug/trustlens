import fs from 'node:fs';
import path from 'node:path';

/**
 * Tiny async database adapter so the rest of the app is driver-agnostic.
 * SQL uses $1, $2... placeholders (PostgreSQL style); they are rewritten for SQLite.
 * Returns: { driver, all(sql, params), get(sql, params), run(sql, params) -> {changes}, exec(sql), close() }
 */
export async function createDb(config) {
  return config.databaseUrl ? createPg(config) : createSqlite(config);
}

async function createSqlite(config) {
  const { DatabaseSync } = await import('node:sqlite');
  if (config.sqlitePath !== ':memory:') fs.mkdirSync(path.dirname(config.sqlitePath), { recursive: true });
  const raw = new DatabaseSync(config.sqlitePath);
  raw.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');
  const cache = new Map();
  // Convert $1, $2... to plain ? placeholders (works on every Node 22 release). `order` remembers which
  // parameter each ? needs, so a $n used twice or out of order still binds correctly.
  const prep = (sql) => {
    let entry = cache.get(sql);
    if (!entry) {
      const order = [];
      const text = sql.replace(/\$(\d+)/g, (_, n) => { order.push(Number(n) - 1); return '?'; });
      entry = { st: raw.prepare(text), order };
      cache.set(sql, entry);
    }
    return entry;
  };
  const args = (e, p) => e.order.map((i) => (p[i] === undefined ? null : p[i]));
  return {
    driver: 'sqlite',
    async all(sql, p = []) { const e = prep(sql); return e.st.all(...args(e, p)).map((r) => ({ ...r })); },
    async get(sql, p = []) { const e = prep(sql); const r = e.st.get(...args(e, p)); return r ? { ...r } : null; },
    async run(sql, p = []) { const e = prep(sql); return { changes: Number(e.st.run(...args(e, p)).changes) }; },
    async exec(sql) { raw.exec(sql); },
    async close() { raw.close(); },
  };
}

async function createPg(config) {
  let pg;
  try {
    pg = (await import('pg')).default;
  } catch {
    throw new Error('DATABASE_URL is set but the "pg" package is missing. Run: npm install');
  }
  const pool = new pg.Pool({ connectionString: config.databaseUrl });
  return {
    driver: 'postgres',
    async all(sql, p = []) { return (await pool.query(sql, p)).rows; },
    async get(sql, p = []) { return (await pool.query(sql, p)).rows[0] || null; },
    async run(sql, p = []) { return { changes: (await pool.query(sql, p)).rowCount }; },
    async exec(sql) { await pool.query(sql); },
    async close() { await pool.end(); },
  };
}

export async function migrate(db) {
  const sql = fs.readFileSync(new URL('./schema.sql', import.meta.url), 'utf8');
  await db.exec(sql);
}
