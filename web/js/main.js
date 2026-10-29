import { html, raw, mount, $, toast, loading, errorBox } from './ui.js';
import { getUser, isAdmin, clearSession } from './api.js';

const routes = [
  [/^\/?$/, () => import('./views/scan.js'), {}],
  [/^\/scan\/([\w-]+)$/, () => import('./views/scan.js'), { auth: true }],
  [/^\/dashboard$/, () => import('./views/dashboard.js'), {}],
  [/^\/history$/, () => import('./views/history.js'), { auth: true }],
  [/^\/community$/, () => import('./views/community.js'), {}],
  [/^\/learn$/, () => import('./views/learn.js'), {}],
  [/^\/keys$/, () => import('./views/account.js'), { auth: true, view: 'keys' }],
  [/^\/login$/, () => import('./views/account.js'), { view: 'login' }],
  [/^\/signup$/, () => import('./views/account.js'), { view: 'signup' }],
  [/^\/admin$/, () => import('./views/admin.js'), { auth: true, admin: true }],
];

const NAV = [
  ['#/', 'Check'], ['#/dashboard', 'Dashboard'], ['#/history', 'History'], ['#/community', 'Community'], ['#/learn', 'Learn'],
];

function renderChrome() {
  const here = location.hash.split('?')[0] || '#/';
  const links = [...NAV, ...(getUser() ? [['#/keys', 'API']] : []), ...(isAdmin() ? [['#/admin', 'Moderation']] : [])];
  mount($('#nav'), html`${links.map(([href, label]) => html`<a href="${href}" ${here === href || (href === '#/' && here.startsWith('#/scan/')) ? raw('aria-current="page"') : ''}>${label}</a>`)}`);
  const u = getUser();
  mount($('#account'), u
    ? html`<span class="who" title="${u.email}">${u.name.split(' ')[0]}</span><button class="btn btn-quiet" id="signout" type="button">Sign out</button>`
    : html`<a class="btn btn-quiet" href="#/login">Sign in</a><a class="btn btn-solid" href="#/signup">Create account</a>`);
  $('#signout')?.addEventListener('click', () => { clearSession(); toast('Signed out'); location.hash = '#/'; });
}

let token = 0;
async function route() {
  const my = ++token;
  const [pathname, qs = ''] = (location.hash.slice(1) || '/').split('?');
  const query = new URLSearchParams(qs);
  const main = $('#main');
  const match = routes.map(([re, load, opts]) => [re.exec(pathname), load, opts]).find(([m]) => m);
  renderChrome();
  if (!match) { mount(main, html`<section class="page"><h1>Page not found</h1><p><a href="#/">Go back to the checker</a></p></section>`); return; }
  const [m, load, opts] = match;
  if (opts.auth && !getUser()) { location.hash = `#/login?next=${encodeURIComponent(location.hash)}`; return; }
  if (opts.admin && !isAdmin()) { mount(main, html`<section class="page"><h1>Moderators only</h1><p>This area is for TrustLens moderators.</p></section>`); return; }
  mount(main, loading());
  try {
    const mod = await load();
    if (my !== token) return;
    main.replaceChildren();
    await mod.render(main, { params: m.slice(1), query, view: opts.view });
    if (my === token) { window.scrollTo(0, 0); }
  } catch (err) {
    if (my === token) mount(main, html`<section class="page">${errorBox(err.message)}</section>`);
  }
}

window.addEventListener('hashchange', route);
window.addEventListener('auth', renderChrome);
route();
