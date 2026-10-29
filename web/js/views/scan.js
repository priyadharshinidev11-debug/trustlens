import { html, raw, esc, mount, $, $$, toast, fmtDate, VERDICT, KIND, errorBox } from '../ui.js';
import { api, getUser } from '../api.js';
import { decodeQr } from '../qr.js';

const EXAMPLES = [
  ['Fake bank link', 'http://sbi-kyc-update.xyz/verify'],
  ['KYC scam SMS', 'Dear customer, your SBI account will be blocked today. Update KYC immediately: http://sbi-kyc-update.xyz/login or call +91 98765 43210'],
  ['"Refund" UPI request', 'upi://pay?pa=refund.care@upi&pn=SBI%20Refund&am=4999&tn=refund'],
  ['Genuine OTP message', '482913 is your OTP for payment of Rs 500 at Amazon. Do not share OTP with anyone. -HDFC Bank'],
];

function guessKind(t) {
  t = t.trim();
  if (!t) return null;
  if (/^upi:\/\//i.test(t) || /^[\w.-]{2,}@[a-z][a-z0-9]+$/i.test(t)) return 'upi';
  if (/^\+?[\d\s-]{8,16}$/.test(t)) return 'phone';
  if (!/\s/.test(t) && (/^https?:\/\//i.test(t) || /^[\w-]+(\.[\w-]+)+(\/|$)/.test(t))) return 'url';
  return 'message';
}

export async function render(el, { params }) {
  if (params[0]) return renderSaved(el, params[0]);

  mount(el, html`
    <section class="page scan-page">
      <h1 class="display">Paste it.<br>We'll check it.</h1>
      <p class="lede">A link, a message, a UPI ID, a phone number or a QR code. You get a verdict and the exact reasons behind it.</p>
      <form id="scan-form" class="scan-box" novalidate>
        <label for="input" class="sr">Link, message, UPI ID or phone number</label>
        <textarea id="input" rows="4" maxlength="5000" placeholder="Paste something you are unsure about, or drop a QR screenshot here" spellcheck="false"></textarea>
        <div class="scan-bar">
          <span class="kind-chip" id="kind-chip" data-kind="">Waiting for input</span>
          <span class="spacer"></span>
          <label class="btn btn-quiet file-btn">Scan QR image<input id="qr" type="file" accept="image/*" hidden></label>
          <button class="btn btn-solid btn-lg" id="go" type="submit">Check</button>
        </div>
      </form>
      <div class="examples" aria-label="Try an example">
        <span>Try:</span>
        ${EXAMPLES.map(([label], i) => html`<button type="button" class="chip" data-ex="${i}">${label}</button>`)}
      </div>
      <p class="fine">${getUser() ? 'Checks are saved to your history. You can delete them any time.' : 'You are checking as a guest, so nothing is saved. Sign in to keep a history.'}</p>
      <div id="result" aria-live="polite"></div>
      <div id="pulse"></div>
    </section>`);

  const input = $('#input', el), chip = $('#kind-chip', el), out = $('#result', el), go = $('#go', el);
  const syncChip = () => {
    const k = guessKind(input.value);
    chip.textContent = k ? `Looks like: ${KIND[k].toLowerCase()}` : 'Waiting for input';
    chip.dataset.kind = k || '';
  };
  input.addEventListener('input', syncChip);
  input.addEventListener('keydown', (e) => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') $('#scan-form', el).requestSubmit(); });

  $$('[data-ex]', el).forEach((b) => b.addEventListener('click', () => { input.value = EXAMPLES[b.dataset.ex][1]; syncChip(); $('#scan-form', el).requestSubmit(); }));

  async function readQr(file) {
    if (!file) return;
    chip.textContent = 'Reading QR code…';
    try {
      const text = await decodeQr(file);
      if (!text) { toast('No QR code found. Try a sharper, closer screenshot.', 'error'); syncChip(); return; }
      input.value = text; syncChip();
      toast('QR code read. Checking where it leads…');
      $('#scan-form', el).requestSubmit();
    } catch (err) { toast(err.message, 'error'); syncChip(); }
  }
  $('#qr', el).addEventListener('change', (e) => { readQr(e.target.files[0]); e.target.value = ''; });
  input.addEventListener('paste', (e) => {
    const f = [...(e.clipboardData?.files || [])].find((x) => x.type.startsWith('image/'));
    if (f) { e.preventDefault(); readQr(f); }
  });
  ['dragover', 'drop'].forEach((ev) => input.addEventListener(ev, (e) => {
    e.preventDefault();
    if (ev === 'drop') { const f = [...e.dataTransfer.files].find((x) => x.type.startsWith('image/')); if (f) readQr(f); }
  }));

  $('#scan-form', el).addEventListener('submit', async (e) => {
    e.preventDefault();
    const value = input.value.trim();
    if (!value) { toast('Paste something to check first', 'error'); input.focus(); return; }
    go.disabled = true; go.textContent = 'Checking…';
    try {
      const result = await api('/api/scan', { method: 'POST', body: { input: value } });
      mount(out, renderResult(result));
      wireResult(out, result);
      out.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
    } catch (err) { mount(out, errorBox(err.message)); }
    finally { go.disabled = false; go.textContent = 'Check'; }
  });

  api('/api/stats/community').then((s) => {
    mount($('#pulse', el), html`<div class="pulse"><strong>${s.reports.toLocaleString('en-IN')}</strong> scams reported by the community, <strong>${s.verified.toLocaleString('en-IN')}</strong> confirmed by moderators. <a href="#/community">See what is going around</a></div>`);
  }).catch(() => {});
}

async function renderSaved(el, id) {
  mount(el, html`<section class="page"><p><a href="#/history">← Back to history</a></p><div id="result"></div></section>`);
  const result = await api(`/api/scans/${encodeURIComponent(id)}`);
  const out = $('#result', el);
  mount(out, html`<p class="fine">Checked on ${fmtDate(result.createdAt)}. Reports and blocklists change, so run it again for a fresh answer.</p>${renderResult(result)}`);
  wireResult(out, result);
}

// ---------- result ----------
const sev = (w) => (w >= 45 ? 'high' : w >= 28 ? 'mid' : 'low');

function annotated(r) {
  const text = r.input;
  const hl = [...r.highlights].sort((a, b) => a.start - b.start);
  let pos = 0; let out = '';
  for (const h of hl) {
    if (h.start < pos) continue;
    out += esc(text.slice(pos, h.start));
    out += `<mark class="mk mk-${sev(h.weight)}" data-rule="${esc(h.rule)}">${esc(text.slice(h.start, h.end))}</mark>`;
    pos = h.end;
  }
  out += esc(text.slice(pos));
  return raw(out);
}

function anatomy(u) {
  const p = u.parts;
  return html`
    <div class="anatomy">
      <p class="anatomy-line" aria-label="Link broken into parts">
        <span class="seg seg-dim">${p.scheme}${p.sub}</span><span class="seg-real"><span class="seg seg-domain">${p.domain}</span><span class="seg seg-suffix">${p.suffix}</span></span><span class="seg seg-dim">${p.rest}</span>
      </p>
      <p class="anatomy-note">The real website is <strong>${u.registrable}</strong>.
        ${u.official ? html`That is the official ${u.official} site.` : u.score >= 30 ? html`It is not a site we recognise as an official one.` : ''}</p>
    </div>`;
}

export function renderResult(r) {
  const v = VERDICT[r.verdict] || VERDICT.unknown;
  const main = r.kind === 'message'
    ? html`<p class="evidence-text">${annotated(r)}</p>`
    : r.kind === 'url' && r.urls[0]
      ? anatomy(r.urls[0])
      : r.kind === 'upi' && r.upi
        ? html`<p class="upi-line"><span class="seg seg-domain">${r.upi.vpa.split('@')[0]}</span><span class="seg seg-suffix">@${r.upi.vpa.split('@')[1] || ''}</span></p>
            ${r.upi.payeeName ? html`<p class="anatomy-note">Payee name shown: <strong>${r.upi.payeeName}</strong></p>` : ''}
            ${r.upi.amount ? html`<p class="anatomy-note">Amount: <strong>₹${Number(r.upi.amount).toLocaleString('en-IN')}</strong> ${r.upi.mode === 'collect' ? '(they are asking you to send this)' : ''}</p>` : ''}`
        : r.kind === 'phone'
          ? html`<p class="upi-line"><span class="seg seg-domain">${r.phones[0]}</span></p>`
          : '';
  const links = r.kind === 'message' ? r.urls : [];
  const reportKind = r.kind === 'message' ? (r.urls.find((u) => u.score >= 30) ? 'url' : r.phones[0] ? 'phone' : 'message') : r.kind;
  const reportValue = reportKind === 'url' ? (r.urls.find((u) => u.score >= 30) || r.urls[0])?.host : reportKind === 'phone' ? r.phones[0] : reportKind === 'upi' ? r.upi?.vpa : r.input.slice(0, 300);
  const reportHref = `#/community?report=1&kind=${reportKind}&value=${encodeURIComponent(reportValue || '')}&category=${encodeURIComponent(r.category || 'Other')}`;

  return html`
    <article class="result verdict-${r.verdict}">
      <header class="verdict">
        <p class="verdict-word">${v.word}</p>
        <p class="verdict-sum">${r.summary}</p>
        <div class="meter" role="img" aria-label="Risk score ${r.score} out of 100" style="--pos:${Math.max(2, Math.min(98, r.score))}%">
          <span class="zone z1"></span><span class="zone z2"></span><span class="zone z3"></span><span class="needle"></span>
        </div>
        <p class="meter-scale"><span>Low</span><strong>${r.kind === 'phone' && r.verdict === 'unknown' ? 'No data' : `Risk ${r.score} of 100`}</strong><span>High</span></p>
      </header>

      <section class="evidence" aria-label="What we looked at">
        <h2 class="h-sm">${r.kind === 'message' ? 'Your message, marked up' : 'What we looked at'}</h2>
        ${main}
        ${links.length ? html`<div class="link-list"><h3 class="h-xs">Links inside</h3>${links.map((u) => anatomy(u))}</div>` : ''}
        ${r.community.length ? html`<p class="community-hit">Reported in the community: ${r.community.map((c) => html`<a href="#/community?q=${encodeURIComponent(c.value)}">${c.value}</a> (${c.category}, ${c.confirms} ${c.confirms === 1 ? 'report' : 'reports'})`)}</p>` : ''}
        <p class="fine">Language detected: ${r.language}</p>
      </section>

      ${r.signals.length ? html`
      <section aria-label="Why this verdict">
        <h2 class="h-sm">Why we say that</h2>
        <ul class="signals">
          ${r.signals.map((s) => html`<li data-rule="${s.from ? 'bad_link' : s.id}">
            <span class="sig-bar sig-${sev(s.weight)}" style="--w:${Math.min(100, s.weight)}%" aria-hidden="true"></span>
            <div><strong>${s.label}</strong><p>${s.detail}</p></div></li>`)}
        </ul>
      </section>` : ''}

      ${r.positives.length ? html`<section aria-label="Reassuring signs"><h2 class="h-sm">In its favour</h2>
        <ul class="signals good">${r.positives.map((p) => html`<li><span class="sig-bar sig-good" aria-hidden="true"></span><div><strong>${p.label}</strong><p>${p.detail}</p></div></li>`)}</ul></section>` : ''}

      <section aria-label="What to do">
        <h2 class="h-sm">What to do</h2>
        <ul class="todo">${r.advice.map((a) => html`<li>${a}</li>`)}</ul>
      </section>

      <footer class="result-actions">
        ${r.verdict !== 'safe' ? html`<a class="btn btn-solid" href="${reportHref}">Report this to the community</a>` : ''}
        <button class="btn btn-quiet" type="button" id="copy-result">Copy summary</button>
        <button class="btn btn-quiet" type="button" id="check-another">Check something else</button>
      </footer>
    </article>`;
}

function wireResult(out, r) {
  out.addEventListener('mouseover', (e) => {
    const li = e.target.closest('.signals li[data-rule]');
    $$('mark.on', out).forEach((m) => m.classList.remove('on'));
    if (li) $$(`mark[data-rule="${CSS.escape(li.dataset.rule)}"]`, out).forEach((m) => m.classList.add('on'));
  });
  $('#copy-result', out)?.addEventListener('click', async () => {
    const text = `TrustLens: ${VERDICT[r.verdict].word} (risk ${r.score}/100). ${r.summary}\nWhy: ${r.signals.slice(0, 3).map((s) => s.label).join('; ') || 'no warning signs'}`;
    try { await navigator.clipboard.writeText(text); toast('Summary copied'); } catch { toast('Could not copy. Select the text manually.', 'error'); }
  });
  $('#check-another', out)?.addEventListener('click', () => { location.hash = '#/'; window.scrollTo(0, 0); $('#input')?.focus(); mount(out, html``); });
}
