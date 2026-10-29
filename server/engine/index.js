import { analyzeUrl, parseLoose } from './url.js';
import { analyzeMessage } from './message.js';
import { analyzeUpi, isUpiLink, isVpa } from './upi.js';
import { extractUrls, extractUpiIds, extractPhones, detectLanguage, noisyOr } from './text.js';

export const DANGEROUS_AT = 60;
export const SUSPICIOUS_AT = 30;
const MAX_INPUT = 5000;

export function detectKind(input) {
  const t = input.trim();
  if (isUpiLink(t) || isVpa(t)) return 'upi';
  if (/^\+?[\d\s-]{8,16}$/.test(t) && t.replace(/\D/g, '').length >= 8) return 'phone';
  if (!/\s/.test(t) && parseLoose(t)) return 'url';
  return 'message';
}

export const verdictFor = (score) => (score >= DANGEROUS_AT ? 'dangerous' : score >= SUSPICIOUS_AT ? 'suspicious' : 'safe');

/**
 * Scan any input. `deps` is optional: { db, config } enables the community blocklist and Safe Browsing lookups.
 * The pure analysis (no deps) is fully deterministic and is what the unit tests exercise.
 */
export async function scan(rawInput, deps = {}) {
  const input = String(rawInput).trim().slice(0, MAX_INPUT);
  const kind = detectKind(input);
  const result = {
    kind, input, language: detectLanguage(input), score: 0, verdict: 'safe', summary: '',
    signals: [], positives: [], advice: [], highlights: [], urls: [], upi: null, phones: [], community: [], category: null,
  };
  const parts = []; // component scores combined at the end
  const lookups = { hosts: [], upi: [], phones: [] };

  if (kind === 'url') {
    const u = analyzeUrl(input);
    result.urls.push(u);
    result.signals.push(...u.signals);
    result.positives.push(...u.positives);
    parts.push(u.score);
    lookups.hosts.push(u.host, u.registrable);
    if (u.signals.some((s) => s.id === 'brand_impersonation')) result.category = 'Phishing link';
  } else if (kind === 'upi') {
    const a = analyzeUpi(input);
    result.upi = a;
    result.signals.push(...a.signals);
    result.positives.push(...a.positives);
    parts.push(a.score);
    if (a.vpa) lookups.upi.push(a.vpa);
    if (a.signals.some((s) => ['collect', 'scammy_name'].includes(s.id))) result.category = 'UPI collect request';
  } else if (kind === 'phone') {
    const digits = input.replace(/\D/g, '');
    const phone = input.trim().startsWith('+') ? `+${digits}` : digits.length === 10 ? `+91${digits}` : `+${digits}`;
    result.phones.push(phone);
    lookups.phones.push(phone);
  } else {
    const m = analyzeMessage(input);
    result.signals.push(...m.signals);
    result.positives.push(...m.positives);
    result.advice.push(...m.advice);
    result.highlights = m.highlights;
    result.category = m.category;
    parts.push(m.score);

    const urls = extractUrls(input).slice(0, 5);
    let worstUrl = 0;
    for (const found of urls) {
      const u = analyzeUrl(found.raw);
      if (!u) continue;
      u.start = found.start; u.end = found.end;
      result.urls.push(u);
      worstUrl = Math.max(worstUrl, u.score);
      lookups.hosts.push(u.host, u.registrable);
      for (const s of u.signals) result.signals.push({ ...s, label: `Link: ${s.label}`, from: u.host });
      result.positives.push(...u.positives.map((p) => ({ ...p, label: `Link: ${p.label}` })));
      if (u.score >= SUSPICIOUS_AT && !result.category) result.category = 'Phishing link';
      if (u.score >= SUSPICIOUS_AT) result.highlights = mergeIn(result.highlights, { start: found.start, end: found.end, rule: 'bad_link', weight: u.score });
    }
    if (worstUrl) parts.push(Math.round(worstUrl * 0.9));

    for (const id of extractUpiIds(input).slice(0, 3)) {
      const a = analyzeUpi(id);
      if (!result.upi) result.upi = a;
      lookups.upi.push(a.vpa);
      for (const s of a.signals) result.signals.push({ ...s, label: `UPI ID: ${s.label}` });
      parts.push(Math.round(a.score * 0.8));
    }
    result.phones = extractPhones(input).slice(0, 3);
    lookups.phones.push(...result.phones);
  }

  // Community blocklist
  if (deps.db) {
    const hits = await communityLookup(deps.db, deps.config, lookups);
    result.community = hits;
    if (hits.length) {
      const best = hits.reduce((a, b) => (b.confirms > a.confirms ? b : a));
      const w = best.status === 'verified' ? 70 : 55;
      result.signals.push({
        id: 'community_report', label: `Reported by the community as ${best.category.toLowerCase()}`,
        detail: `${best.value} was flagged by ${best.confirms} ${best.confirms === 1 ? 'person' : 'people'}${best.status === 'verified' ? ' and verified by a moderator' : ''}.`, weight: w,
      });
      parts.push(w);
      result.category = result.category || best.category;
    }
  }

  // Optional Google Safe Browsing
  if (deps.config?.safeBrowsingKey && result.urls.length) {
    const flagged = await safeBrowsing(deps.config.safeBrowsingKey, result.urls.map((u) => u.href));
    if (flagged) {
      result.signals.push({ id: 'safe_browsing', label: 'Flagged as dangerous by Google Safe Browsing', detail: `Threat type: ${flagged}.`, weight: 80 });
      parts.push(80);
      result.category = result.category || 'Phishing link';
    }
  }

  result.score = parts.length ? noisyOr(parts) : 0;
  result.signals.sort((a, b) => b.weight - a.weight);

  if (kind === 'phone') {
    result.verdict = result.community.length ? verdictFor(result.score) : 'unknown';
    result.summary = result.community.length ? 'This number has been reported' : 'No reports for this number yet';
  } else {
    result.verdict = verdictFor(result.score);
    result.summary = summarise(result);
  }
  result.advice = buildAdvice(result);
  return result;
}

function summarise(r) {
  if (r.verdict === 'safe') {
    if (r.positives.length) return r.positives[0].label;
    return r.signals.length ? `Minor note: ${r.signals[0].label.toLowerCase()}` : 'No warning signs found';
  }
  const top = r.signals[0];
  const more = r.signals.length - 1;
  return top ? `${top.label}${more > 0 ? ` (+${more} more warning sign${more > 1 ? 's' : ''})` : ''}` : 'Suspicious';
}

function buildAdvice(r) {
  const out = [...new Set(r.advice)];
  if (r.verdict === 'dangerous') {
    out.unshift('Do not click, reply, install anything or send money.');
    out.push('If you already shared an OTP, PIN or card details, call your bank now and report at 1930 or cybercrime.gov.in.');
  } else if (r.verdict === 'suspicious') {
    out.unshift('Do not act on this yet. Check through the official app or a website address you type yourself.');
  } else if (r.verdict === 'unknown') {
    out.push('Unknown does not mean safe. If the caller asked for money, OTPs or remote access, hang up.');
  } else {
    out.push('No tool can promise something is safe. Never share your OTP or UPI PIN with anyone.');
  }
  return out.slice(0, 6);
}

function mergeIn(list, h) {
  const out = list.filter((x) => x.end <= h.start || x.start >= h.end);
  out.push(h);
  return out.sort((a, b) => a.start - b.start);
}

async function communityLookup(db, config, { hosts, upi, phones }) {
  const min = config?.blocklistThreshold ?? 3;
  const checks = [['url', [...new Set(hosts.map((h) => h.replace(/^www\./, '')))]], ['upi', [...new Set(upi)]], ['phone', [...new Set(phones)]]];
  const found = [];
  for (const [kind, values] of checks) {
    for (const value of values) {
      const row = await db.get(
        `SELECT id, kind, value, category, status, confirms, disputes FROM reports
         WHERE kind = $1 AND value = $2 AND (status = 'verified' OR (status = 'pending' AND confirms - disputes >= $3))
         ORDER BY confirms DESC LIMIT 1`, [kind, value, min]);
      if (row) found.push(row);
    }
  }
  return found;
}

async function safeBrowsing(key, urls) {
  try {
    const res = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${encodeURIComponent(key)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'trustlens', clientVersion: '1.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'], threatEntryTypes: ['URL'], threatEntries: urls.map((url) => ({ url })),
        },
      }),
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return null;
    const data = await res.json();
    return data.matches?.[0]?.threatType?.replace(/_/g, ' ').toLowerCase() || null;
  } catch {
    return null; // never let an optional integration break a scan
  }
}
