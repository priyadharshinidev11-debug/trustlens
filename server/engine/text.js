import { TLD_FOR_BARE_DOMAINS } from './data.js';

export function levenshtein(a, b) {
  if (a === b) return 0;
  const m = a.length, n = b.length;
  if (!m || !n) return Math.max(m, n);
  let prev = Array.from({ length: n + 1 }, (_, j) => j);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[n];
}

const CONFUSABLE = { 0: 'o', 1: 'l', 3: 'e', 4: 'a', 5: 's', 7: 't', $: 's', '@': 'a', '!': 'i' };
/** Collapse look-alike characters so "paypa1" and "rnicrosoft" compare equal to the real names. */
export function skeleton(s) {
  return s.toLowerCase().replace(/[013457$@!]/g, (c) => CONFUSABLE[c]).replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/[-_.]/g, '');
}

/** Combine independent warning weights (0-100) into one score: each extra signal adds, with diminishing returns. */
export function noisyOr(weights) {
  const safe = weights.filter((w) => w > 0).reduce((acc, w) => acc * (1 - Math.min(w, 99) / 100), 1);
  return Math.round((1 - safe) * 100);
}

const TLD_ALT = TLD_FOR_BARE_DOMAINS.join('|');
const URL_RE = new RegExp(
  String.raw`(?<![@\w.-])((?:https?:\/\/|www\.)[^\s<>"')\]]+|(?:[a-z0-9-]+\.)+(?:${TLD_ALT})(?![a-z0-9-])(?:\/[^\s<>"')\]]*)?)`,
  'gi',
);

export function extractUrls(text) {
  const out = [];
  const seen = new Set();
  for (const m of text.matchAll(URL_RE)) {
    const raw = m[1].replace(/[.,;:!?]+$/, '');
    if (!raw || seen.has(raw.toLowerCase())) continue;
    seen.add(raw.toLowerCase());
    out.push({ raw, start: m.index, end: m.index + raw.length });
  }
  return out;
}

export function extractUpiIds(text) {
  const re = /(?<![\w.-])[a-z0-9._-]{2,}@[a-z][a-z0-9]{1,}(?![a-z0-9-]*\.[a-z])/gi;
  return [...new Set([...text.matchAll(re)].map((m) => m[0].toLowerCase()))];
}

export function extractPhones(text) {
  const found = new Set();
  for (const m of text.matchAll(/(?<![\d])(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)/g)) {
    const digits = m[0].replace(/\D/g, '');
    found.add('+91' + digits.slice(-10));
  }
  for (const m of text.matchAll(/(?<![\d])\+(?!91)\d{1,3}[\s-]?\d{6,12}(?!\d)/g)) found.add('+' + m[0].replace(/\D/g, ''));
  return [...found];
}

export function detectLanguage(text) {
  const count = (re) => (text.match(re) || []).length;
  const dev = count(/[\u0900-\u097F]/g), tam = count(/[\u0B80-\u0BFF]/g), lat = count(/[A-Za-z]/g);
  const top = Math.max(dev, tam, lat);
  if (!top) return 'Unknown';
  if (top === tam) return 'Tamil';
  if (top === dev) return 'Hindi';
  return 'English / Latin script';
}
