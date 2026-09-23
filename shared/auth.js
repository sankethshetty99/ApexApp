// Google sign-in for the apex gate (sankethshetty.me, www.sankethshetty.me),
// allow-listed to one address. Copied from the LearnApp production restyle
// (2026-09-22): the sign-in button is our own dark pill, not the GIS
// renderButton iframe; the token client POSTs an access token to
// /auth/callback, which is verified against Google's tokeninfo endpoint
// server-side (aud == GOOGLE_CLIENT_ID, email verified, allow-listed).
//
// The session cookie is named `sid_apex` (unique per app) and scoped to
// sankethshetty.me via COOKIE_DOMAIN. SESSION_SECRET is a real secret, set
// once as a Cloudflare secret binding; GOOGLE_CLIENT_ID is public by design.

const COOKIE = 'sid_apex';

const SESSION_DAYS = 30;
const GOOGLE_CERTS = 'https://www.googleapis.com/oauth2/v3/certs';
const ISSUERS = new Set(['accounts.google.com', 'https://accounts.google.com']);

const enc = new TextEncoder();

// --- base64url ---------------------------------------------------------------

function fromB64url(s) {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4);
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function toB64url(bytes) {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Constant-time compare. A fast `===` on a signature leaks how much of a
 *  forgery was right, one byte at a time. */
function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// --- Google's ID token -------------------------------------------------------

let certs = { at: 0, keys: [] };

async function googleKeys() {
  if (certs.keys.length && Date.now() - certs.at < 3_600_000) return certs.keys;
  const res = await fetch(GOOGLE_CERTS);
  if (!res.ok) throw new Error(`Google keys unavailable (${res.status})`);
  const { keys } = await res.json();
  certs = { at: Date.now(), keys };
  return keys;
}

/** Verify a Google ID token and return its claims. Throws on anything off. */
export async function verifyIdToken(jwt, clientId) {
  const parts = String(jwt || '').split('.');
  if (parts.length !== 3 || parts.some((x) => !/^[A-Za-z0-9_-]+$/.test(x))) {
    throw new Error('malformed token');
  }
  const [h, p, s] = parts;

  let header;
  try { header = JSON.parse(new TextDecoder().decode(fromB64url(h))); }
  catch { throw new Error('malformed token'); }
  const jwk = (await googleKeys()).find((k) => k.kid === header.kid);
  if (!jwk) throw new Error('unknown signing key');

  const key = await crypto.subtle.importKey(
    'jwk', jwk, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5', key, fromB64url(s), enc.encode(`${h}.${p}`));
  if (!ok) throw new Error('bad signature');

  let claims;
  try { claims = JSON.parse(new TextDecoder().decode(fromB64url(p))); }
  catch { throw new Error('malformed token'); }
  const now = Math.floor(Date.now() / 1000);
  if (!ISSUERS.has(claims.iss)) throw new Error('wrong issuer');
  if (claims.aud !== clientId) throw new Error('wrong audience');
  if (claims.exp <= now) throw new Error('token expired');
  if (claims.iat > now + 300) throw new Error('token from the future');
  if (claims.email_verified !== true) throw new Error('email not verified');
  return claims;
}

// --- our own session cookie --------------------------------------------------

function allowList(env) {
  return (env.ALLOWED_EMAILS || 'sankethshetty007@gmail.com')
    .split(',').map((s) => s.trim().toLowerCase()).filter(Boolean);
}

async function signingKey(env) {
  if (!env.SESSION_SECRET) throw new Error('SESSION_SECRET is not set');
  return crypto.subtle.importKey('raw', enc.encode(env.SESSION_SECRET),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
}

async function mint(env, email) {
  const payload = toB64url(enc.encode(JSON.stringify({
    email, exp: Date.now() + SESSION_DAYS * 86_400_000,
  })));
  const sig = new Uint8Array(await crypto.subtle.sign(
    'HMAC', await signingKey(env), enc.encode(payload)));
  return `${payload}.${toB64url(sig)}`;
}

async function open(env, value) {
  const [payload, sig] = String(value).split('.');
  if (!payload || !sig) return null;
  const want = new Uint8Array(await crypto.subtle.sign(
    'HMAC', await signingKey(env), enc.encode(payload)));
  if (!sameBytes(fromB64url(sig), want)) return null;
  try {
    const claims = JSON.parse(new TextDecoder().decode(fromB64url(payload)));
    if (claims.exp <= Date.now()) return null;
    // Re-checked on every request, not just at sign-in: pulling an address out
    // of the list should end its sessions, not wait thirty days for them.
    if (!allowList(env).includes(String(claims.email).toLowerCase())) return null;
    return claims.email;
  } catch { return null; }
}

function cookies(request) {
  const out = {};
  for (const part of (request.headers.get('Cookie') || '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k) out[k] = v.join('=');
  }
  return out;
}

function setCookie(env, value, maxAge) {
  const domain = env.COOKIE_DOMAIN ? `; Domain=${env.COOKIE_DOMAIN}` : '';
  return `${COOKIE}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/${domain}; Max-Age=${maxAge}`;
}

/** The signed-in address, or null. */
export async function session(request, env) {
  const raw = cookies(request)[COOKIE];
  return raw ? open(env, raw) : null;
}

// --- the gate ----------------------------------------------------------------

/** Returns a Response to send back when the request may not proceed, or null
 *  when it may. */
export async function guard(request, env, url, opts = {}) {
  if (await session(request, env)) return null;

  if (url.pathname.startsWith('/api/')) {
    return new Response(JSON.stringify({ error: 'sign in', login: '/login' }), {
      status: 401,
      headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
    });
  }
  if (url.pathname === '/login') return loginPage(env, opts);
  return Response.redirect(new URL('/login', url).toString(), 302);
}

export async function handleAuth(request, env, url) {
  if (url.pathname === '/auth/logout') {
    return new Response(null, { status: 302, headers: {
      location: '/login', 'set-cookie': setCookie(env, '', 0) } });
  }

  if (url.pathname !== '/auth/callback' || request.method !== 'POST') {
    return new Response('not found', { status: 404 });
  }
  if (!env.GOOGLE_CLIENT_ID) return json401('sign-in is not configured');

  // Requiring JSON is the CSRF guard. A cross-site form post cannot set this
  // content type without a preflight, and this endpoint answers no preflight -
  // so the only thing that can reach here is our own page.
  if (!(request.headers.get('content-type') || '').includes('application/json')) {
    return json401('unexpected content type');
  }

  let access_token;
  try { ({ access_token } = await request.json()); } catch { return json401('bad body'); }

  let tokenEmail;
  try {
    const ti = await fetch('https://oauth2.googleapis.com/tokeninfo?access_token=' + encodeURIComponent(String(access_token || '')));
    if (!ti.ok) throw new Error('token rejected by Google');
    const info = await ti.json();
    if (info.aud !== env.GOOGLE_CLIENT_ID) throw new Error('wrong audience');
    if (info.email_verified !== 'true') throw new Error('email not verified');
    if (!info.email) throw new Error('no email on token');
    tokenEmail = String(info.email);
  } catch (err) {
    return json401(`Sign-in rejected: ${err.message}`);
  }

  const email = tokenEmail.toLowerCase();
  if (!allowList(env).includes(email)) {
    // Named on purpose: the usual reason for landing here is being signed into
    // the wrong Google account in this browser, and a bare "access denied"
    // sends people hunting for a permissions problem that does not exist.
    return json401(`${tokenEmail} is not on the list for this app.`);
  }

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      'content-type': 'application/json',
      'cache-control': 'no-store',
      'set-cookie': setCookie(env, await mint(env, email), SESSION_DAYS * 86_400),
    },
  });
}

function json401(error) {
  return new Response(JSON.stringify({ error }), {
    status: 401,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store' },
  });
}

// --- the login page ----------------------------------------------------------

// The sign-in button is our own dark pill, not Google's rendered iframe: the
// GIS button iframe renders light and shows as a conspicuous white rectangle
// on this dark page. Clicking the pill opens Google's OAuth popup via the
// token client; the access token is POSTed to /auth/callback and verified
// against Google's tokeninfo endpoint server-side.
export function loginPage(env, { title = 'sankethshetty.me', message = '' } = {}) {
  const configured = Boolean(env.GOOGLE_CLIENT_ID);
  const esc = (t) => String(t).replace(/[<&\"]/g, (c) => ({ '<': '&lt;', '&': '&amp;', '"': '&quot;' }[c]));

  const body = configured ? `
    <button id="gsign" class="gsign" type="button">
      <svg viewBox="0 0 24 24" aria-hidden="true"><path fill="#4285F4" d="M23.5 12.3c0-.9-.1-1.5-.3-2.3H12v4.5h6.5c-.1 1.1-.8 2.7-2.4 3.8l-.1.1 3.5 2.7.2.1c2.2-2 3.8-5 3.8-8.9z"/><path fill="#34A853" d="M12 24c3.2 0 6-1.1 7.9-2.9l-3.8-2.9c-1 .7-2.4 1.2-4.1 1.2-3.1 0-5.8-2.1-6.8-5l-.1.1-3.7 2.9v.1C3.5 21.3 7.5 24 12 24z"/><path fill="#FBBC05" d="M5.2 14.4c-.2-.7-.4-1.5-.4-2.4s.1-1.7.4-2.4l-.1-.1-3.6-2.8-.1.1C.5 8.5 0 10.1 0 12s.5 3.5 1.4 5.1l3.8-2.7z"/><path fill="#EA4335" d="M12 4.7c1.8 0 3 .8 3.7 1.4l3.3-3.2C17.9 1.1 15.2 0 12 0 7.5 0 3.5 2.7 1.4 6.9l3.8 2.9c1-2.9 3.7-5.1 6.8-5.1z"/></svg>
      <span>Sign in with Google</span>
    </button>
    <p class="msg" id="msg">${esc(message)}</p>
    <script src="https://accounts.google.com/gsi/client" async defer><\/script>
    <script>
      const msg = document.getElementById('msg');
      function say(t) { msg.textContent = t; }

      window.onGoogleToken = async (res) => {
        if (!res || res.error || !res.access_token) { say('Sign-in was cancelled.'); return; }
        say('Checking\u2026');
        try {
          const r = await fetch('/auth/callback', {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ access_token: res.access_token }),
          });
          if (r.ok) { location.href = '/'; return; }
          say((await r.json().catch(() => ({}))).error || 'Sign-in failed.');
        } catch { say('Could not reach the server.'); }
      };

      window.onload = () => {
        if (!window.google || !window.google.accounts || !window.google.accounts.oauth2) {
          say('Could not load Google sign-in.'); return;
        }
        const tc = google.accounts.oauth2.initTokenClient({
          client_id: ${JSON.stringify(env.GOOGLE_CLIENT_ID)},
          scope: 'openid email profile',
          callback: window.onGoogleToken,
        });
        document.getElementById('gsign').addEventListener('click', () => {
          say('');
          tc.requestAccessToken();
        });
      };
    <\/script>`
    : `<p class="msg">Sign-in is not configured, so nothing is open.
       Set <code>GOOGLE_CLIENT_ID</code> on this Worker.</p>`;

  return new Response(`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>Sign in</title>
<style>
  :root { color-scheme: dark; }
  body { margin:0; min-height:100dvh; display:grid; place-items:center;
         background:#0b0b0d; color:#fff; text-align:center; padding:24px;
         font:400 16px/1.5 ui-sans-serif,-apple-system,"SF Pro Text",system-ui,sans-serif;
         -webkit-font-smoothing:antialiased; }
  .box { max-width:23rem; }
  h1 { margin:0 0 8px; font-size:26px; letter-spacing:-0.02em; }
  .lede { margin:0 0 22px; color:rgba(255,255,255,.6); font-size:14.5px; }
  .msg { margin:18px 0 0; color:#ffc44d; font-size:13.5px; }
  .msg:empty { display:none; }
  code { font-size:13px; color:rgba(255,255,255,.75); }
  .gsign { display:inline-flex; align-items:center; gap:10px; margin:0 auto;
         background:#17171b; color:#fff; border:1px solid rgba(255,255,255,.16);
         border-radius:999px; padding:13px 24px; cursor:pointer;
         font:500 15px/1 ui-sans-serif,-apple-system,"SF Pro Text",system-ui,sans-serif;
         -webkit-font-smoothing:antialiased; }
  .gsign:hover { background:#202027; border-color:rgba(255,255,255,.3); }
  .gsign:active { transform:translateY(1px); }
  .gsign svg { width:18px; height:18px; display:block; }
</style>
</head><body>
  <div class="box">
    <h1>${esc(title)}</h1>
    <p class="lede">One account has access.</p>
    ${body}
  </div>
</body></html>`, {
    status: configured ? 200 : 503,
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
  });
}

