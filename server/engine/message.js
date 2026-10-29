import { noisyOr, extractUrls } from './text.js';

/**
 * Rule-based scam message detector. Each rule has a weight (0-100), a report category and an advice line.
 * `latin` patterns are matched case-insensitively with word boundaries; `native` patterns cover Hindi and
 * Tamil script (starter coverage, extend as you collect real examples).
 */
const RULES = [
  {
    id: 'otp_request', category: 'OTP / PIN theft', weight: 45, negatable: true,
    label: 'Asks you to share a one-time code, PIN or password',
    advice: 'No bank, app or officer will ever ask for your OTP, PIN or CVV. Never share them.',
    latin: [/\b(share|send|tell|give|provide|enter|reply with|read out)\b.{0,25}\b(otp|pin|cvv|password|passcode|mpin)\b/gi, /\b(otp|cvv|mpin|pin)\b.{0,20}\b(share|send|tell|batao|bhejo)\b/gi, /\botp (batao|bataye|share karo|bhejo)\b/gi],
    native: [/ओटीपी/gu, /ஓடிபி|ஒடிபி/gu],
  },
  {
    id: 'sensitive_info', category: 'OTP / PIN theft', weight: 38, negatable: true,
    label: 'Asks for card, Aadhaar, PAN or banking details',
    advice: 'Do not send identity or card details over SMS, WhatsApp or a link.',
    latin: [/\b(aadhaar|aadhar|pan|card number|cvv|expiry|net ?banking|login details)\b.{0,30}\b(send|share|reply|enter|submit|update)\b/gi],
    native: [],
  },
  {
    id: 'account_block', category: 'Bank / KYC block', weight: 30,
    label: 'Threatens to block or close your account, card or SIM',
    advice: 'Check your account only in the official app or by calling the number printed on your card.',
    latin: [/\b(account|a\/c|card|sim|number|wallet|upi|kyc)\b.{0,40}\b(block(ed)?|suspend(ed)?|deactivat(ed|e)|freez(e|ing)|frozen|clos(e|ed)|expire(d|s)?|disconnect(ed)?)\b/gi, /\b(band ho (jaye|jayega|jaega)|block ho (jaye|jayega))\b/gi],
    native: [/(खाता|अकाउंट|कार्ड|सिम).{0,30}(बंद|ब्लॉक|निलंबित)/gu, /(கணக்கு|கார்டு|சிம்).{0,30}(முடக்க|நிறுத்த|தடை)/gu],
  },
  {
    id: 'kyc_update', category: 'Bank / KYC block', weight: 30,
    label: 'Demands a KYC, PAN or Aadhaar update',
    advice: 'KYC updates are done at your bank branch or inside the official app, never through a link in a message.',
    latin: [/\b(kyc|pan|aadhaar|aadhar)\b.{0,40}\b(update|verify|verification|expir(e|ed|y)|pending|link(ing)?|mandatory)\b/gi, /\b(update|verify|complete|renew)\b.{0,15}\b(kyc|pan|aadhaar|aadhar)\b/gi, /\bkyc (update|verify) kar/gi],
    native: [/केवाईसी|केवाइसी/gu, /கேஒய்சி|கேவைசி/gu],
  },
  {
    id: 'urgency', category: 'Other', weight: 18,
    label: 'Creates panic with a deadline',
    advice: 'Scammers rush you so you cannot think. Pause and verify first.',
    latin: [/\b(urgent(ly)?|immediately|right now|within \d+ ?(hours?|hrs?|minutes?|mins?)|last (chance|warning|reminder)|expires? (today|soon|in)|act now|final notice|turant|jaldi)\b/gi, /\babhi (update|verify|click)\b/gi],
    native: [/तुरंत|जल्दी/gu, /உடனடியாக|உடனே|அவசரம்/gu],
  },
  {
    id: 'upi_collect', category: 'UPI collect request', weight: 50,
    label: 'Tells you to enter your UPI PIN to "receive" money',
    advice: 'You never need your UPI PIN to receive money. A PIN prompt means money is leaving your account.',
    latin: [/\b(collect request|accept (the )?(payment )?request|approve (the )?(request|collect)|(enter|put) (your )?(upi )?pin to (receive|get|claim)|pin to receive|scan (this )?qr (to )?receive)\b/gi],
    native: [],
  },
  {
    id: 'prize', category: 'Fake prize or lottery', weight: 32,
    label: 'Claims you won a prize, lottery or reward',
    advice: 'You cannot win a contest you did not enter. Delete it.',
    latin: [/\b(you (have )?won|winner|lottery|lucky draw|jackpot|congratulations.{0,40}(won|selected)|claim (your )?(prize|reward|gift))\b/gi],
    native: [/इनाम|लॉटरी/gu, /பரிசு|லாட்டரி/gu],
  },
  {
    id: 'fee_request', category: 'Other', weight: 30,
    label: 'Asks you to pay a fee or deposit first',
    advice: 'Genuine prizes, jobs, loans and refunds never require an upfront payment.',
    latin: [/\b(registration fee|processing fee|refundable deposit|security deposit|customs (fee|charge|duty)|clearance fee|courier charge|release fee|activation fee)\b/gi, /\b(pay|transfer|send|deposit)\b.{0,30}(₹|rs\.?|inr)\s?\d/gi],
    native: [],
  },
  {
    id: 'job_task', category: 'Job or task scam', weight: 35,
    label: 'Offers easy money for simple online tasks',
    advice: 'Easy-money task jobs, "like and earn" and Telegram work groups are a common scam. Do not pay to "unlock" earnings.',
    latin: [/\b(work from home|part[- ]time (job|work)|earn (₹|rs\.?|\$)?\s?\d[\d,]*\s*(per|a|\/)\s*(day|hour|week)|like (and )?(subscribe|youtube)|tasks? (to|and) earn|daily income|telegram (group|channel))\b/gi],
    native: [],
  },
  {
    id: 'authority', category: 'Digital arrest / fake authority', weight: 45,
    label: 'Claims to be police, CBI, customs, TRAI or a court',
    advice: 'There is no such thing as a "digital arrest". Real agencies do not video-call, demand money or ask you to stay on the line. Hang up and call 1930.',
    latin: [/\b(cbi|ncb|trai|rbi|customs|police|cyber ?(crime|cell)|enforcement directorate|narcotics|income tax dep(t|artment)|supreme court|high court)\b.{0,80}\b(arrest|warrant|case|illegal|parcel|money laundering|summons|fir|drugs)\b/gi, /\bdigital arrest\b/gi],
    native: [],
  },
  {
    id: 'parcel', category: 'Parcel or courier', weight: 28,
    label: 'Says a parcel or delivery is stuck',
    advice: 'Track parcels only on the courier or shop\'s own app or website.',
    latin: [/\b(parcel|package|courier|shipment|delivery)\b.{0,60}\b(held|stuck|pending|failed|undelivered|address|customs|redeliver|reschedule)\b/gi],
    native: [],
  },
  {
    id: 'utility', category: 'Electricity / utility bill', weight: 32,
    label: 'Says your electricity, gas or water will be cut tonight',
    advice: 'Pay bills only through the utility\'s official app or counter, and never call numbers inside an SMS.',
    latin: [/\b(electricity|power|eb|tneb|tangedco|gas|water|bill)\b.{0,50}\b(disconnect(ed|ion)?|cut|tonight|last date|unpaid|overdue)\b/gi],
    native: [/மின்சாரம்|மின் இணைப்பு/gu],
  },
  {
    id: 'remote_access', category: 'Remote-access app', weight: 55,
    label: 'Asks you to install a screen-sharing or remote-control app',
    advice: 'Remote-control apps let a stranger see your screen and empty your bank account. Uninstall them if you installed one.',
    latin: [/\b(anydesk|teamviewer|quicksupport|rustdesk|airdroid|ultraviewer|screen ?shar(e|ing))\b/gi],
    native: [],
  },
  {
    id: 'apk', category: 'Fake app (APK)', weight: 40,
    label: 'Pushes you to install an app from a link',
    advice: 'Install apps only from Google Play or the App Store. Fake "bank" and "PM scheme" apps steal your SMS and OTPs.',
    latin: [/\.apk\b/gi, /\b(install|download)\b.{0,30}\b(app|apk|application)\b.{0,30}\b(update|verify|claim|kyc|reward)\b/gi],
    native: [],
  },
  {
    id: 'investment', category: 'Investment or crypto', weight: 35,
    label: 'Promises guaranteed or very high investment returns',
    advice: 'Guaranteed returns do not exist. Check any adviser on the SEBI website before investing.',
    latin: [/\b(guaranteed|assured) (returns?|profit)|double your (money|investment)|100% (profit|returns?)|insider tip|crypto (signal|investment)|(stock|trading) (tip|group|signal)s?|returns? of \d+%/gi],
    native: [],
  },
  {
    id: 'refund', category: 'Refund scam', weight: 28,
    label: 'Offers a refund you must claim',
    advice: 'Genuine refunds go back to your original payment method automatically. You never need to "accept" one.',
    latin: [/\b(refund|reversal|chargeback)\b.{0,40}\b(click|link|process|pending|claim|upi|account)\b/gi],
    native: [],
  },
  {
    id: 'threat', category: 'Other', weight: 22,
    label: 'Threatens legal action or penalties',
    advice: 'Legal notices are sent by post or official email, not by threatening SMS.',
    latin: [/\b(legal action|fir will|face (legal|arrest)|penalty|fine of|your (number|account|sim) will be)\b/gi],
    native: [],
  },
  {
    id: 'contact_chat', category: 'Other', weight: 15,
    label: 'Asks you to continue on WhatsApp or Telegram',
    advice: 'Be careful moving to private chat apps with someone who contacted you first.',
    latin: [/\b(whatsapp|telegram)\b.{0,30}\+?\d[\d\s-]{8,}/gi, /\b(contact|message|chat) (me |us )?(on|via) (whatsapp|telegram)\b/gi],
    native: [],
  },
  {
    id: 'click_bait', category: 'Phishing link', weight: 12,
    label: 'Pushes you to tap a link',
    advice: 'Do not tap links in unexpected messages. Type the website address yourself.',
    latin: [/\b(click|tap|open)\b.{0,15}\b(link|here|below)\b/gi],
    native: [],
  },
];

const NEGATION_INSIDE = /\b(do not|don't|dont|never|not to|won't)\b/i;
const NEGATION_BEFORE = /\b(do not|don't|dont|never|not to|won't|will never|should not|shouldn't)\b[^.\n]{0,18}$/i;

// Links are analysed separately by the URL engine, so blank them out (same length, so indexes still line up)
// to stop message rules from matching words inside a web address.
function maskUrls(text) {
  let out = text;
  for (const u of extractUrls(text)) out = out.slice(0, u.start) + ' '.repeat(u.end - u.start) + out.slice(u.end);
  return out;
}

export function analyzeMessage(original) {
  const text = maskUrls(original);
  const signals = [];
  const highlights = [];
  const advice = new Set();

  for (const rule of RULES) {
    const matches = [];
    for (const re of [...rule.latin, ...rule.native]) {
      for (const m of text.matchAll(new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g'))) {
        if (!m[0]) continue;
        if (rule.negatable && (NEGATION_BEFORE.test(text.slice(Math.max(0, m.index - 30), m.index)) || NEGATION_INSIDE.test(m[0]))) continue;
        matches.push({ start: m.index, end: m.index + m[0].length, text: m[0] });
      }
    }
    if (!matches.length) continue;
    signals.push({ id: rule.id, label: rule.label, detail: `Matched: "${matches[0].text.slice(0, 80)}"`, weight: rule.weight, category: rule.category });
    advice.add(rule.advice);
    for (const m of matches) highlights.push({ start: m.start, end: m.end, rule: rule.id, weight: rule.weight });
  }

  const positives = [];
  const looksLikeOtpNotice = /\b\d{4,8}\b.{0,30}\b(otp|one[- ]time (password|code))\b|\b(otp|one[- ]time (password|code))\b.{0,30}\b\d{4,8}\b/i.test(text);
  if (looksLikeOtpNotice && /\b(do not|don't|never)\b.{0,15}\bshare\b/i.test(text)) {
    positives.push({ id: 'otp_notice', label: 'Looks like a normal OTP notice', detail: 'It delivers a code and warns you not to share it, which is how genuine banks write. Still, only use it for a payment you started yourself.' });
  }

  const topCategory = signals.filter((s) => s.category !== 'Other').sort((a, b) => b.weight - a.weight)[0]?.category
    || signals.sort((a, b) => b.weight - a.weight)[0]?.category || null;

  return {
    signals,
    positives,
    highlights: mergeHighlights(highlights),
    advice: [...advice],
    category: topCategory,
    score: noisyOr(signals.map((s) => s.weight)),
  };
}

// Merge overlapping ranges, keeping the rule with the highest weight for each merged range.
function mergeHighlights(list) {
  const sorted = [...list].sort((a, b) => a.start - b.start || b.end - a.end);
  const out = [];
  for (const h of sorted) {
    const last = out[out.length - 1];
    if (last && h.start < last.end) {
      last.end = Math.max(last.end, h.end);
      if (h.weight > last.weight) { last.weight = h.weight; last.rule = h.rule; }
    } else out.push({ ...h });
  }
  return out;
}
