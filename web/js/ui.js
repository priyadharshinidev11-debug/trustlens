// Tiny templating: values are HTML-escaped unless wrapped with raw(). html`` returns raw markup so templates nest.
export const raw = (s) => ({ __raw: String(s) });
export const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const part = (v) => (v && v.__raw !== undefined ? v.__raw : Array.isArray(v) ? v.map(part).join('') : esc(v));
export function html(strings, ...vals) {
  let out = '';
  strings.forEach((s, i) => { out += s + (i < vals.length ? part(vals[i]) : ''); });
  return raw(out);
}
export const mount = (el, tpl) => { el.innerHTML = tpl.__raw; };
export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

export function toast(message, kind = 'info') {
  const el = document.createElement('div');
  el.className = `toast toast-${kind}`;
  el.textContent = message;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

export const fmtDate = (iso) => new Date(iso).toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' });
export const fmtDay = (iso) => new Date(iso).toLocaleDateString('en-IN', { day: 'numeric', month: 'short' });

export const VERDICT = {
  dangerous: { word: 'Dangerous', short: 'Dangerous' },
  suspicious: { word: 'Suspicious', short: 'Suspicious' },
  safe: { word: 'Looks safe', short: 'Safe' },
  unknown: { word: 'Unknown', short: 'Unknown' },
};
export const KIND = { url: 'Link', message: 'Message', upi: 'UPI ID', phone: 'Phone number' };

export const loading = (text = 'Loading') => html`<p class="loading" role="status">${text}…</p>`;
export const errorBox = (msg) => html`<p class="error-box" role="alert">${msg}</p>`;
export const empty = (title, body, action = '') => html`<div class="empty"><h3>${title}</h3><p>${body}</p>${raw(action)}</div>`;
