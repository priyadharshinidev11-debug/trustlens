import { html, mount, $, $$, toast, fmtDate, KIND, empty, errorBox } from '../ui.js';
import { api } from '../api.js';

export async function render(el) {
  const ov = await api('/api/admin/overview');
  mount(el, html`
    <section class="page">
      <h1 class="h-lg">Moderation</h1>
      <dl class="facts">
        <div><dt>Members</dt><dd>${ov.users}</dd></div><div><dt>Checks run</dt><dd>${ov.scans}</dd></div>
        <div><dt>Waiting for review</dt><dd>${ov.reportsPending}</dd></div><div><dt>Verified</dt><dd>${ov.reportsVerified}</dd></div><div><dt>Rejected</dt><dd>${ov.reportsRejected}</dd></div>
      </dl>
      <div class="tabs" role="tablist">
        ${['pending', 'verified', 'rejected'].map((s, i) => html`<button role="tab" class="tab" data-tab="${s}" aria-selected="${i === 0}">${s[0].toUpperCase() + s.slice(1)}</button>`)}
      </div>
      <div id="queue"></div>
    </section>`);

  let status = 'pending';
  const queue = $('#queue', el);
  async function load() {
    try {
      const { items } = await api(`/api/admin/reports?status=${status}`);
      mount(queue, items.length ? html`${items.map((x) => html`
        <article class="report" data-id="${x.id}">
          <header><span class="tag">${KIND[x.kind]}</span><span class="tag tag-cat">${x.category}</span><span class="tag">${x.confirms} confirm · ${x.disputes} dispute</span></header>
          <p class="report-value">${x.value}</p>
          ${x.description ? html`<p class="report-desc">${x.description}</p>` : ''}
          <footer>
            ${status !== 'verified' ? html`<button class="btn btn-solid" data-set="verified" type="button">Verify</button>` : ''}
            ${status !== 'rejected' ? html`<button class="btn btn-quiet danger-text" data-set="rejected" type="button">Reject</button>` : ''}
            ${status !== 'pending' ? html`<button class="btn btn-quiet" data-set="pending" type="button">Move to pending</button>` : ''}
            <small>${x.reporter || 'seeded'} · ${fmtDate(x.createdAt)}</small>
          </footer>
        </article>`)}` : empty('Nothing here', `No ${status} reports.`));
    } catch (err) { mount(queue, errorBox(err.message)); }
  }
  el.addEventListener('click', async (e) => {
    const tab = e.target.closest('[data-tab]');
    if (tab) { status = tab.dataset.tab; $$('.tab', el).forEach((t) => t.setAttribute('aria-selected', t === tab)); load(); return; }
    const b = e.target.closest('[data-set]');
    if (!b) return;
    try {
      await api(`/api/admin/reports/${b.closest('.report').dataset.id}/status`, { method: 'POST', body: { status: b.dataset.set } });
      toast(`Marked ${b.dataset.set}`); load();
    } catch (err) { toast(err.message, 'error'); }
  });
  await load();
}
