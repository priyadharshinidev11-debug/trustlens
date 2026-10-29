import { domainToUnicode } from 'node:url';
import {
  BRANDS, SUSPICIOUS_TLDS, SHORTENERS, SECOND_LEVEL_SUFFIXES, RISKY_WORDS, RISKY_EXTENSIONS,
} from './data.js';
import { levenshtein, skeleton, noisyOr } from './text.js';

const sig = (id, label, detail, weight) => ({ id, label, detail, weight });
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

export function splitHost(host) {
  const labels = host.split('.');
  const last2 = labels.slice(-2).join('.');
  const take = SECOND_LEVEL_SUFFIXES.has(last2) ? 3 : 2;
  const registrable = labels.slice(-take).join('.');
  const suffix = labels.slice(-(take - 1)).join('.');
  const sub = labels.slice(0, -take).join('.');
  return { registrable, suffix, sub, domainLabel: labels[Math.max(0, labels.length - take)] };
}

function findOfficial(registrable) {
  return BRANDS.find((b) => b.domains.includes(registrable)) || null;
}

export function parseLoose(raw) {
  const text = raw.trim();
  const hadScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(text);
  try {
    const url = new URL(hadScheme ? text : `http://${text.replace(/^\/\//, '')}`);
    if (!['http:', 'https:'].includes(url.protocol)) return null;
    if (!url.hostname || (!url.hostname.includes('.') && !IPV4.test(url.hostname))) return null;
    return { url, hadScheme };
  } catch {
    return null;
  }
}

export function analyzeUrl(raw) {
  const parsed = parseLoose(raw);
  if (!parsed) return null;
  const { url, hadScheme } = parsed;
  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  const isIp = IPV4.test(host);
  const { registrable, suffix, sub, domainLabel } = isIp
    ? { registrable: host, suffix: '', sub: '', domainLabel: host }
    : splitHost(host);
  const official = isIp ? null : findOfficial(registrable);
  const pathAndQuery = decodeURIComponent_safe(url.pathname + url.search).toLowerCase();
  const signals = [];
  const positives = [];

  if (isIp) signals.push(sig('ip_host', 'Uses a raw IP address instead of a website name', `Real services use names like "${'example.com'}", not ${host}.`, 35));
  if (url.username || url.password || /^https?:\/\/[^/]*@/i.test(raw)) {
    signals.push(sig('userinfo', 'Contains "@" before the real address', 'Everything before the @ is ignored by the browser; it is a trick to make a fake link look real.', 30));
  }
  if (!isIp && host.split('.').some((l) => l.startsWith('xn--'))) {
    signals.push(sig('punycode', 'Domain uses look-alike international characters', `Shown by browsers as "${domainToUnicode(host)}" but registered as ${host}.`, 25));
  }
  if (url.protocol === 'http:' && hadScheme) signals.push(sig('no_https', 'Not encrypted (http, not https)', 'Legitimate banks and shops always use https.', 10));
  if (url.port && !['80', '443'].includes(url.port)) signals.push(sig('odd_port', `Unusual port :${url.port}`, 'Normal websites do not need a custom port.', 12));

  if (!isIp && !official) {
    const tld = suffix.split('.').pop();
    if (SUSPICIOUS_TLDS.has(tld)) signals.push(sig('risky_tld', `".${tld}" is a cheap, frequently abused ending`, 'Scam sites favour these because they cost almost nothing to register.', 15));
    if (SHORTENERS.has(registrable)) signals.push(sig('shortener', 'Shortened link hides the real destination', 'You cannot see where it goes until you open it. Ask the sender for the full link.', 30));

    // Brand impersonation
    const labelsText = host.replace(/\./g, '-');
    const tokens = labelsText.split(/[-_]/);
    let impersonated = null;
    let how = '';
    for (const b of BRANDS) {
      for (const k of b.keys) {
        if (tokens.includes(k) || (k.length >= 6 && host.includes(k))) { impersonated = b; how = 'contains'; break; }
      }
      if (impersonated) break;
    }
    if (!impersonated) {
      const sk = skeleton(domainLabel);
      for (const b of BRANDS) {
        for (const d of b.domains) {
          const target = d.split('.')[0];
          if (target === domainLabel || target.length < 5) continue;
          const dist = levenshtein(sk, skeleton(target));
          if (dist === 0 || (dist === 1 && target.length >= 6)) { impersonated = b; how = dist === 0 ? 'lookalike' : 'typo'; break; }
        }
        if (impersonated) break;
      }
    }
    if (impersonated) {
      const detail = how === 'contains'
        ? `The name appears in the address, but the real site is ${registrable}, which does not belong to ${impersonated.name}. Official: ${impersonated.domains[0]}.`
        : `${registrable} is a near-copy of ${impersonated.domains[0]} with swapped or altered characters.`;
      signals.push(sig('brand_impersonation', `Pretends to be ${impersonated.name}`, detail, how === 'contains' ? 40 : how === 'lookalike' ? 60 : 50));
    } else {
      const inPath = BRANDS.find((b) => b.keys.some((k) => k.length >= 4 && pathAndQuery.includes(k)));
      if (inPath) signals.push(sig('brand_in_path', `Mentions ${inPath.name} in the page address`, `The website itself (${registrable}) is not ${inPath.name}.`, 15));
    }

    const words = RISKY_WORDS.filter((w) => (host + pathAndQuery).includes(w));
    if (words.length) signals.push(sig('risky_words', `Pressure words in the address: ${words.slice(0, 4).join(', ')}`, 'Scam pages reuse words like verify, update, KYC and claim.', Math.min(3, words.length) * 7));

    if (sub.split('.').filter(Boolean).length >= 3) signals.push(sig('deep_subdomain', 'Many layers before the real domain', `Only "${registrable}" matters. The rest (${sub}) is decoration.`, 12));
    if ((host.match(/-/g) || []).length >= 3) signals.push(sig('hyphens', 'Many hyphens in the domain', 'Long hyphenated names are typical of throw-away scam domains.', 10));
    if (host.length > 40) signals.push(sig('long_host', 'Unusually long domain name', `${host.length} characters.`, 10));
    if ((host.match(/\d/g) || []).length >= 4) signals.push(sig('digits', 'Lots of digits in the domain', 'Auto-generated scam domains often end with random numbers.', 8));
  }

  const lowerPath = url.pathname.toLowerCase();
  const ext = RISKY_EXTENSIONS.find((e) => lowerPath.endsWith(e.ext));
  if (ext && !official) signals.push(sig('risky_file', ext.label, 'Never install apps or programs from a link sent to you. Use the official Play Store or website.', ext.weight));
  if (raw.length > 100) signals.push(sig('long_url', 'Very long link', `${raw.length} characters, often used to bury the real destination.`, 8));
  if ((raw.match(/%[0-9a-f]{2}/gi) || []).length >= 4) signals.push(sig('encoded', 'Heavily encoded characters in the link', 'Encoding can hide what the link really does.', 8));

  if (official && url.protocol === 'https:') {
    positives.push({ id: 'official', label: `Official ${official.name} website`, detail: `${registrable} is a known domain of ${official.name}.` });
  }

  let score = noisyOr(signals.map((s) => s.weight));
  if (official && url.protocol === 'https:' && !signals.some((s) => ['userinfo', 'punycode', 'ip_host'].includes(s.id))) score = Math.min(score, 8);

  const rest = url.pathname + url.search + url.hash;
  const subPrefix = sub ? sub + '.' : '';
  return {
    input: raw,
    href: url.href.length > 300 ? url.href.slice(0, 300) + '…' : url.href,
    host,
    registrable,
    official: official ? official.name : null,
    parts: {
      scheme: hadScheme ? `${url.protocol}//` : '',
      sub: subPrefix,
      domain: isIp ? host : registrable.slice(0, registrable.length - suffix.length - 1),
      suffix: isIp ? '' : `.${suffix}`,
      rest: rest === '/' ? '' : rest.length > 80 ? rest.slice(0, 80) + '…' : rest,
    },
    score,
    signals,
    positives,
  };
}

function decodeURIComponent_safe(s) {
  try { return decodeURIComponent(s); } catch { return s; }
}
