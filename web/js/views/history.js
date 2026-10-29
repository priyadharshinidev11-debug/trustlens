import { html, mount, $, $$, toast, fmtDate, VERDICT, KIND, empty, errorBox } from '../ui.js';
import { api } from '../api.js';

export async function render(el) {
  mount(el, html`
    <section class="page">
      <div class="page-head"><h1 class="h-lg">History</h1>
        <div class="filters">
          <label class="sr" for="f-verdict">Verdict</label>
          <select id="f-verdict"><option value="">All verdicts</option><option value="dangerous">Dangerous</option><option value="suspicious">Suspicious</option><option value="safe">Safe</option><option value="unknown">Unknown</option></select>
          <label class="sr" for="f-kind">Type</label>
          <select id="f-kind"><option value="">All types</option><option value="url">Links</option><option value="message">Messages</option><option value="upi">UPI IDs</option><option value="phone">Phone numbers</option></select>
        </div></div>
      <div id="list"></div>
      <p><button id="more" class="btn btn-quiet" type="button" hidden>Load more</button> <button id="clear" class="btn btn-quiet danger-text" type="button" hidden>Delete all history</button></p>
    </section>`);

  const list = $('#list', el); const more = $('#more', el); const clear = $('#clear', el);
  let offset = 0; const PAGE = 20;

  async function load(reset) {
    if (reset) { offset = 0; list.replaceChildren(); }
    const q = new URLSearchParams({ limit: PAGE, offset });
    if ($('#f-verdict', el).value) q.set('verdict', $('#f-verdict', el).value);
    if ($('#f-kind', el).value) q.set('kind', $('#f-kind', el).value);
    try {
      const { items, total } = await api(`/api/scans?${q}`);
      if (reset && !items.length) { mount(list, empty('No checks here yet', 'Checks you run while signed in show up here.', '<a class="btn btn-solid" href="#/">Check something</a>')); more.hidden = true; clear.hidden = true; return; }
      list.insertAdjacentHTML('beforeend', html`${items.map((s) => html`
        <div class="row" data-id="${s.id}">
          <a class="row-main" href="#/scan/${s.id}">
            <span class="pill pill-${s.verdict}">${VERDICT[s.verdict]?.short || s.verdict}</span>
            <span class="row-text"><strong>${s.input}</strong><small>${KIND[s.kind] || s.kind} · ${fmtDate(s.created_at)} · risk ${s.score}</small></span>
          </a>
          <button class="btn btn-quiet" type="button" data-del="${s.id}" aria-label="Delete this check">Delete</button>
        </div>`)}`.__raw);
      offset += items.length; more.hidden = offset >= total; clear.hidden = false;
    } catch (err) { mount(list, errorBox(err.message)); }
  }

  el.addEventListener('click', async (e) => {
    const del = e.target.closest('[data-del]');
    if (del) {
      try { await api(`/api/scans/${del.dataset.del}`, { method: 'DELETE' }); del.closest('.row').remove(); toast('Deleted'); } catch (err) { toast(err.message, 'error'); }
    }
  });
  more.addEventListener('click', () => load(false));
  clear.addEventListener('click', async () => {
    if (!confirm('Delete your entire check history? This cannot be undone.')) return;
    try { await api('/api/scans', { method: 'DELETE' }); toast('History deleted'); load(true); } catch (err) { toast(err.message, 'error'); }
  });
  $$('select', el).forEach((s) => s.addEventListener('change', () => load(true)));
  await load(true);
}
