const KEY = 'trustlens.session';
let session = null;
try { session = JSON.parse(localStorage.getItem(KEY) || 'null'); } catch { session = null; }

export const getUser = () => session?.user || null;
export const isAdmin = () => session?.user?.role === 'admin';

export function setSession(s) {
  session = s;
  try { localStorage.setItem(KEY, JSON.stringify(s)); } catch { /* private mode */ }
  window.dispatchEvent(new Event('auth'));
}
export function clearSession() {
  session = null;
  try { localStorage.removeItem(KEY); } catch { /* ignore */ }
  window.dispatchEvent(new Event('auth'));
}

export async function api(path, { method = 'GET', body } = {}) {
  let res;
  try {
    res = await fetch(path, {
      method,
      headers: { 'Content-Type': 'application/json', ...(session?.token ? { Authorization: `Bearer ${session.token}` } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new Error('Cannot reach TrustLens. Check your internet connection and try again.');
  }
  let data = {};
  try { data = await res.json(); } catch { /* empty body */ }
  if (res.status === 401 && session && !path.startsWith('/api/auth/login')) {
    clearSession();
    location.hash = '#/login';
  }
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}
