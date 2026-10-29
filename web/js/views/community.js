import { html, mount, $, $$, toast, fmtDate, KIND, empty, errorBox } from '../ui.js';
import { api, getUser } from '../api.js';

const PLACEHOLDER = {
  url: 'e.g. sbi-kyc-update.xyz', upi: 'e.g. refund.support@upi', phone: 'e.g. +91 98765 43210', message: 'Paste the scam message',
};

export async function render(el, { query }) {
  const meta = await api('/api/meta');
  const user = getUser();
  const wantsForm = query.get('report') === '1';

  mount(el, html`
    <section class="page">
      <h1 class="h-lg">Community reports</h1>
      <p class="lede sm">Scams people have reported. When enough people confirm one, TrustLens starts warning everyone who checks it. Moderators verify the rest.</p>

      <details class="report-form" id="report-details" ${wantsForm ? 'open' : ''}>
        <summary class="btn btn-solid">Report a scam</summary>
        ${user ? html`
        <form id="report" novalidate>
          <div class="grid2">
            <label>What are you reporting
              <select name="kind" id="r-kind">${Object.entries(KIND).map(([k, v]) => html`<option value="${k}" ${query.get('kind') === k ? 'selected' : ''}>${v}</option>`)}</select></label>
            <label>Type of scam
              <select name="category">${meta.categories.map((c) => html`<option ${query.get('category') === c ? 'selected' : ''}>${c}</option>`)}</select></label>
          </div>
          <label>Details <input name="value" id="r-value" type="text" maxlength="2000" value="${query.get('value') || ''}" placeholder="${PLACEHOLDER[query.get('kind') || 'url']}" required></label>
          <label>What happened? (optional) <textarea name="description" rows="3" maxlength="600" placeholder="How did it reach you? What did they ask for?"></textarea></label>
          <p class="fine">Do not include your own OTPs, card numbers or other private details.</p>
          <button class="btn btn-solid" type="submit">Submit report</button>
        </form>` : html`<p class="fine pad">Please <a href="#/login?next=${encodeURIComponent('#/community?report=1')}">sign in</a> to report a scam. It stops people from flooding the list with fake reports.</p>`}
      </details>

      <div class="filters bar">
        <label class="sr" for="q">Search</label><input id="q" type="search" placeholder="Search reports" value="${query.get('q') || ''}">
        <label class="sr" for="c-kind">Type</label>
        <select id="c-kind"><option value="">All types</option>${Object.entries(KIND).map(([k, v]) => html`<option value="${k}">${v}</option>`)}</select>
        <label class="sr" for="c-sort">Order</label>
        <select id="c-sort"><option value="new">Newest</option><option value="top">Most confirmed</option></select>
      </div>
      <div id="feed"></div>
    </section>`);

  const feed = $('#feed', el);
  async function load() {
    const q = new URLSearchParams({ sort: $('#c-sort', el).value });
    if ($('#q', el).value.trim()) q.set('q', $('#q', el).value.trim());
    if ($('#c-kind', el).value) q.set('kind', $('#c-kind', el).value);
    try {
      const { items } = await api(`/api/reports?${q}`);
      mount(feed, items.length ? html`${items.map(card)}` : empty('No reports match', 'Try a different search, or report the scam yourself.'));
    } catch (err) { mount(feed, errorBox(err.message)); }
  }

  const card = (x) => html`
    <article class="report" data-id="${x.id}">
      <header><span class="tag">${KIND[x.kind]}</span><span class="tag tag-cat">${x.category}</span>
        ${x.status === 'verified' ? html`<span class="tag tag-ok">Verified</span>` : ''}</header>
      <p class="report-value">${x.value}</p>
      ${x.description ? html`<p class="report-desc">${x.description}</p>` : ''}
      <footer>
        <button type="button" class="vote ${x.myVote === 1 ? 'on' : ''}" data-vote="1" aria-pressed="${x.myVote === 1}">I saw this too · ${x.confirms}</button>
        <button type="button" class="vote ${x.myVote === -1 ? 'on' : ''}" data-vote="-1" aria-pressed="${x.myVote === -1}">Not a scam · ${x.disputes}</button>
        <small>${fmtDate(x.createdAt)}</small>
      </footer>
    </article>`;

  feed.addEventListener('click', async (e) => {
    const b = e.target.closest('[data-vote]');
    if (!b) return;
    if (!getUser()) { toast('Sign in to vote', 'error'); location.hash = `#/login?next=${encodeURIComponent('#/community')}`; return; }
    const id = b.closest('.report').dataset.id;
    const want = Number(b.dataset.vote);
    const mine = b.classList.contains('on') ? 0 : want;
    try {
      const updated = await api(`/api/reports/${id}/vote`, { method: 'POST', body: { vote: mine } });
      b.closest('.report').outerHTML = card(updated).__raw;
    } catch (err) { toast(err.message, 'error'); }
  });

  $('#report', el)?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = Object.fromEntries(new FormData(e.target));
    try {
      const res = await api('/api/reports', { method: 'POST', body: f });
      toast(res.merged ? 'Already reported. We added your confirmation.' : 'Thanks. Your report is live.');
      e.target.reset(); $('#report-details', el).open = false; load();
    } catch (err) { toast(err.message, 'error'); }
  });
  $('#r-kind', el)?.addEventListener('change', (e) => { $('#r-value', el).placeholder = PLACEHOLDER[e.target.value]; });
  let t; $('#q', el).addEventListener('input', () => { clearTimeout(t); t = setTimeout(load, 250); });
  $$('select', feed.parentElement).forEach((s) => s.addEventListener('change', load));
  await load();
}
