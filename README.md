# ApexApp

`sankethshetty.me` and `www.sankethshetty.me`: a Google login gate, nothing
else. Same sign-in as the learn app and the doors (one allow-listed address:
sankethshetty007@gmail.com).

## Why this exists

The portfolio moved to a Notion page. The apex no longer hosts the static
site; it is just the login. The Notion page hotlinks its images from
`https://sankethshetty.me/assets/...`, so `/assets/*` is served publicly and
everything else sits behind the gate.

## Layout

- `src/worker.js` — routing: `/assets/*` public, everything else gated;
  `pm.sankethshetty.me` 301s to the public Notion portfolio page
- `shared/auth.js` — the shared Google sign-in (copied from LearnApp's
  production restyle: dark pill + initTokenClient, no GIS renderButton).
  Session cookie is `sid_apex`.
- `public/assets/` — the 41 portfolio images, copied from PortfolioSite
- `wrangler.toml` — routes for the apex + www, plain-text `[vars]`
- `.github/workflows/deploy.yml` — deploys on push to `production`

## Secrets

`SESSION_SECRET` is a real secret, set once as a Cloudflare secret binding
(`wrangler secret put SESSION_SECRET`). It is intentionally different from
the learn/doors secret: sessions here are separate, nothing breaks.
`GOOGLE_CLIENT_ID` is public by design and lives in `[vars]`.
