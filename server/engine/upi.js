import { UPI_HANDLES, BRANDS } from './data.js';
import { noisyOr } from './text.js';

const sig = (id, label, detail, weight) => ({ id, label, detail, weight });
const VPA_RE = /^[a-z0-9._-]{2,}@[a-z][a-z0-9]{1,}$/i;
const SCAMMY_NAME = /(refund|support|care|help|kyc|reward|cashback|lottery|prize|claim|customer|service|official|verify|loan|insurance|govt|gov)/i;

export function isUpiLink(s) { return /^upi:\/\//i.test(s.trim()); }
export function isVpa(s) { return VPA_RE.test(s.trim()); }

export function parseUpi(input) {
  const t = input.trim();
  if (isUpiLink(t)) {
    try {
      const u = new URL(t);
      const p = u.searchParams;
      return { vpa: (p.get('pa') || '').toLowerCase(), name: p.get('pn') || '', amount: p.get('am') || '', note: p.get('tn') || '', mode: u.hostname.toLowerCase(), isLink: true };
    } catch { return { vpa: '', isLink: true, mode: '' }; }
  }
  return { vpa: t.toLowerCase(), isLink: false, mode: '', name: '', amount: '', note: '' };
}

export function analyzeUpi(input) {
  const p = parseUpi(input);
  const signals = [];
  const positives = [];
  const [local = '', handle = ''] = p.vpa.split('@');

  if (!isVpa(p.vpa)) {
    signals.push(sig('invalid_vpa', 'This is not a valid UPI ID', 'A UPI ID looks like name@bank.', 20));
  } else {
    if (UPI_HANDLES.has(handle)) positives.push({ id: 'known_handle', label: `"@${handle}" is a recognised UPI handle`, detail: 'That only shows which bank or app hosts the ID. It says nothing about who owns it.' });
    else signals.push(sig('unknown_handle', `"@${handle}" is not a handle we recognise`, 'It may be new or fake. Verify the payee before paying.', 18));
    if (SCAMMY_NAME.test(local)) signals.push(sig('scammy_name', 'ID name sounds like a refund, support or reward desk', 'Fraudsters register IDs such as "refund.support@..." to look official. Real companies do not collect refunds through UPI IDs.', 32));
  }

  if (p.mode === 'collect') signals.push(sig('collect', 'This is a request for money, not a payment to you', 'Approving a collect request sends money out of your account.', 40));
  const amount = Number(p.amount);
  if (p.isLink && amount > 0) {
    signals.push(sig('prefilled_amount', `Link pre-fills a payment of ₹${amount.toLocaleString('en-IN')}`, 'If someone says you are receiving money, a pre-filled amount means you are paying.', amount >= 10000 ? 30 : 20));
  }
  const claimed = p.name && BRANDS.find((b) => b.keys.some((k) => k.length >= 4 && p.name.toLowerCase().includes(k)));
  if (claimed) signals.push(sig('claimed_brand', `Payee name claims to be ${claimed.name}`, 'Companies publish their payment details on their official site. Confirm there first.', 22));

  return { input, vpa: p.vpa, payeeName: p.name || null, amount: p.amount || null, mode: p.mode || null, isLink: p.isLink, score: noisyOr(signals.map((s) => s.weight)), signals, positives };
}
