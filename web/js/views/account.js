import { html, mount, $, toast, fmtDate, empty, errorBox } from '../ui.js';
import { api, setSession, getUser } from '../api.js';

export async function render(el, ctx) {
  return ctx.view === 'keys' ? renderKeys(el) : renderAuth(el, ctx);
}

function renderAuth(el, { view, query }) {
  const signup = view === 'signup';
  const next = query.get('next') || '#/';
  mount(el, html`
    <section class="page narrow">
      <h1 class="h-lg">${signup ? 'Create your account' : 'Welcome back'}</h1>
      <p class="lede sm">${signup ? 'Keep a history of your checks, vote on community reports and get an API key.' : 'Sign in to see your history and report scams.'}</p>
      <form id="auth" class="stack" novalidate>
        ${signup ? html`<label>Your name <input name="name" autocomplete="name" required minlength="2"></label>` : ''}
        <label>Email <input name="email" type="email" autocomplete="email" required></label>
        <label>Password <input name="password" type="password" autocomplete="${signup ? 'new-password' : 'current-password'}" required minlength="8">
          ${signup ? html`<small class="fine">At least 8 characters.</small>` : ''}</label>
        <p id="auth-error" class="error-box" role="alert" hidden></p>
        <button class="btn btn-solid btn-lg" type="submit">${signup ? 'Create account' : 'Sign in'}</button>
      </form>
      <p class="fine">${signup ? html`Already have an account? <a href="#/login">Sign in</a>` : html`New here? <a href="#/signup">Create an account</a>`}</p>
    </section>`);

  $('#auth', el).addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = $('#auth-error', el); err.hidden = true;
    const btn = e.target.querySelector('button'); btn.disabled = true;
    try {
      const session = await api(signup ? '/api/auth/signup' : '/api/auth/login', { method: 'POST', body: Object.fromEntries(new FormData(e.target)) });
      setSession(session);
      toast(`Signed in as ${session.user.name}`);
      location.hash = next.startsWith('#/') ? next : '#/';
    } catch (ex) { err.textContent = ex.message; err.hidden = false; btn.disabled = false; }
  });
}

async function renderKeys(el) {
  const origin = location.origin;
  mount(el, html`
    <section class="page">
      <h1 class="h-lg">API access</h1>
      <p class="lede sm">Check links and messages from your own app, bot or website. Limit: 120 requests a minute per key.</p>
      <form id="newkey" class="inline-form"><label class="sr" for="kn">Key name</label><input id="kn" name="name" placeholder="Name this key, e.g. WhatsApp bot" maxlength="60" required><button class="btn btn-solid" type="submit">Create key</button></form>
      <div id="fresh"></div>
      <div id="keys"></div>
      <h2 class="h-sm top-gap">Try it</h2>
      <pre class="code" tabindex="0">curl -X POST ${origin}/api/v1/scan \\
  -H "X-API-Key: YOUR_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"input":"http://sbi-kyc-update.xyz/login"}'</pre>
      <p class="fine">The response has <code>verdict</code> (safe, suspicious, dangerous or unknown), a 0 to 100 <code>score</code>, and the <code>signals</code> behind it.</p>
    </section>`);

  async function load() {
    try {
      const { items } = await api('/api/keys');
      mount($('#keys', el), items.length ? html`${items.map((k) => html`
        <div class="row"><div class="row-main"><span class="row-text"><strong>${k.name}</strong><small>${k.prefix}… · created ${fmtDate(k.createdAt)} · ${k.lastUsedAt ? `last used ${fmtDate(k.lastUsedAt)}` : 'never used'}</small></span></div>
        <button class="btn btn-quiet danger-text" type="button" data-revoke="${k.id}">Revoke</button></div>`)}`
        : empty('No keys yet', 'Create one above to start using the API.'));
    } catch (err) { mount($('#keys', el), errorBox(err.message)); }
  }
  $('#newkey', el).addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const k = await api('/api/keys', { method: 'POST', body: { name: $('#kn', el).value } });
      mount($('#fresh', el), html`<div class="fresh-key"><p><strong>Copy your key now.</strong> We only show it once.</p><code>${k.key}</code><button class="btn btn-quiet" type="button" id="copy-key">Copy</button></div>`);
      $('#copy-key', el).addEventListener('click', async () => { try { await navigator.clipboard.writeText(k.key); toast('Key copied'); } catch { toast('Select and copy the key manually', 'error'); } });
      e.target.reset(); load();
    } catch (err) { toast(err.message, 'error'); }
  });
  el.addEventListener('click', async (e) => {
    const b = e.target.closest('[data-revoke]');
    if (!b || !confirm('Revoke this key? Apps using it will stop working.')) return;
    try { await api(`/api/keys/${b.dataset.revoke}`, { method: 'DELETE' }); toast('Key revoked'); load(); } catch (err) { toast(err.message, 'error'); }
  });
  await load();
}
