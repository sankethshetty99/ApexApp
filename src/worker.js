// sankethshetty.me and www.sankethshetty.me: a Google login gate, nothing else.
//
// Strangers get the sign-in page (shared/shared/auth.js, allow-listed to one
// address, same as the learn app and the doors). The one person on the list
// gets a minimal landing page with a way back out.
//
// /assets/* is served WITHOUT authentication. The public Notion portfolio
// page hotlinks its images from https://sankethshetty.me/assets/..., and a
// gate on those URLs would break every image on that page (a notion.site
// visitor has no session cookie). The images are already public; the gate
// covers everything else.

import { guard, handleAuth, session, loginPage } from '../shared/auth.js';

function landing() {
  return new Response(`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>sankethshetty.me</title>
<style>
  :root { color-scheme: dark; }
  body { margin:0; min-height:100dvh; display:grid; place-items:center;
         background:#0b0b0d; color:#fff; text-align:center; padding:24px;
         font:400 16px/1.5 ui-sans-serif,-apple-system,"SF Pro Text",system-ui,sans-serif;
         -webkit-font-smoothing:antialiased; }
  h1 { margin:0 0 6px; font-size:26px; letter-spacing:-0.02em; }
  p { margin:0 0 20px; color:rgba(255,255,255,.6); font-size:14.5px; }
  a { color:#c6f24e; text-decoration:none; font-size:14px; }
  .pm { display:inline-block; margin:0 0 22px; padding:12px 26px;
        border:1px solid rgba(255,255,255,.16); border-radius:999px;
        color:#fff; font-size:15px; font-weight:500; }
  .pm:hover { background:#202027; border-color:rgba(255,255,255,.3); }
</style>
</head><body>
  <div>
    <h1>sankethshetty.me</h1>
    <p>Signed in.</p>
    <p><a class="pm" href="https://pm.sankethshetty.me">Portfolio</a></p>
    <a href="/auth/logout">Sign out</a>
  </div>
</body></html>`, {
    headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Public portfolio images. No auth (see note at top).
    if (url.pathname === '/assets' || url.pathname.startsWith('/assets/')) {
      return env.ASSETS.fetch(request);
    }

    if (url.pathname.startsWith('/auth/')) {
      return handleAuth(request, env, url);
    }

    const email = await session(request, env);
    if (!email) {
      // /login renders the sign-in page; anything else bounces there.
      if (url.pathname === '/login') return loginPage(env, { title: 'sankethshetty.me' });
      return Response.redirect(new URL('/login', url).toString(), 302);
    }

    if (url.pathname === '/login') {
      return Response.redirect(new URL('/', url).toString(), 302);
    }
    return landing();
  },
};
