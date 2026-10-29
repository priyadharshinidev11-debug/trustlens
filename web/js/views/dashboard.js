import { html, raw, mount, $, VERDICT, KIND, fmtDay } from '../ui.js';
import { api, getUser } from '../api.js';

const COLORS = { dangerous: 'var(--danger)', suspicious: 'var(--warn)', safe: 'var(--safe)', unknown: 'var(--muted)' };

function bars(days) {
  const W = 560, H = 150, pad = 6, bw = (W - pad * 2) / days.length;
  const max = Math.max(1, ...days.map((d) => d.safe + d.suspicious + d.dangerous + d.unknown));
  let svg = '';
  days.forEach((d, i) => {
    let y = H - 18;
    for (const k of ['safe', 'suspicious', 'dangerous', 'unknown']) {
      const h = (d[k] / max) * (H - 36);
      if (!h) continue;
      y -= h;
      svg += `<rect x="${pad + i * bw + 3}" y="${y.toFixed(1)}" width="${(bw - 6).toFixed(1)}" height="${h.toFixed(1)}" rx="2" fill="${COLORS[k]}"><title>${fmtDay(d.date)}: ${d[k]} ${k}</title></rect>`;
    }
    if (i % 3 === 0) svg += `<text x="${pad + i * bw + bw / 2}" y="${H - 3}" text-anchor="middle" class="axis">${fmtDay(d.date)}</text>`;
  });
  return raw(`<svg viewBox="0 0 ${W} ${H}" class="chart" role="img" aria-label="Checks per day over the last 14 days">${svg}</svg>`);
}

export async function render(el) {
  const user = getUser();
  const [mine, community] = await Promise.all([user ? api('/api/stats/me') : null, api('/api/stats/community')]);
  const maxTrend = Math.max(1, ...community.trending.map((t) => t.n));

  mount(el, html`
    <section class="page">
      ${mine ? html`
        <h1 class="display sm">${mine.total === 0 ? 'Nothing checked yet.' : html`You have checked ${mine.total} ${mine.total === 1 ? 'thing' : 'things'}.`}
          ${mine.verdicts.dangerous ? html`<span class="muted-h">${mine.verdicts.dangerous} ${mine.verdicts.dangerous === 1 ? 'was' : 'were'} dangerous.</span>` : ''}</h1>
        <div class="legend">${['safe', 'suspicious', 'dangerous', 'unknown'].map((k) => html`<span><i style="--c:${COLORS[k]}"></i>${VERDICT[k].short} ${mine.verdicts[k]}</span>`)}</div>
        ${bars(mine.days)}
        ${mine.total ? html`<p class="fine">${Object.entries(mine.kinds).map(([k, n]) => `${n} ${(KIND[k] || k).toLowerCase()}${n === 1 ? '' : 's'}`).join(', ')}.</p>` : html`<p><a class="btn btn-solid" href="#/">Run your first check</a></p>`}`
      : html`
        <h1 class="display sm">See what you have been checking.</h1>
        <p class="lede">Sign in to keep a history and see how many scams you have dodged.</p>
        <p><a class="btn btn-solid" href="#/signup">Create a free account</a> <a class="btn btn-quiet" href="#/login">Sign in</a></p>`}

      <h2 class="h-md top-gap">What is going around this month</h2>
      ${community.trending.length ? html`<ul class="trend">${community.trending.map((t) => html`<li><span>${t.category}</span><span class="trend-bar" style="--w:${(t.n / maxTrend) * 100}%"></span><b>${t.n}</b></li>`)}</ul>`
        : html`<p class="muted">No reports yet this month. <a href="#/community">Be the first to report one.</a></p>`}
      <p class="fine">${community.reports} community reports, ${community.verified} verified, ${community.checks} checks by members.</p>
    </section>`);
}
