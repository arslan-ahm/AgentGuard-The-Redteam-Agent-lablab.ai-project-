# Demo store

Owner: Sohaib (brief 6.5, SUBMISSION_PACK item 7). A small, **deliberately flawed** Flask shop used as the demo scan target.

> ## WARNING: DO NOT DEPLOY THIS PUBLICLY
> Every flaw below is on purpose: stack traces, an open redirect, reflected input, an unauthenticated admin page, insecure cookies. Run it only on your own machine, or as the single demo target for an AgentGuard scan. Never put real data or real secrets in it, and never point it at a production domain.

## Run

```bash
cd scripts/demo-store
uv sync
uv run python app.py            # http://127.0.0.1:5050  (HOST / PORT env vars override)
uv run pytest -q                # asserts every flaw below exists
```

Seed data is `seed/products.json` (4 products), so every run is identical. Demo login: `demo@example.com` / `demo-pass` (documented on purpose, not a secret).

AgentGuard refuses loopback and private addresses as targets (policy, brief 6.9), so for a real scan expose the store on a public hostname you control (for example a temporary tunnel, with `HOST=0.0.0.0`) and tear it down afterwards.

## Flaws and the check that should find them

| Flaw | Where | Expected check_id |
|---|---|---|
| Broken link (`/old-sale` returns 404) | `/` | `qa.links_assets` |
| 404 script asset (`/static/missing.js`) | `/about` | `qa.links_assets`, `qa.console_network_errors` |
| `console.error('demo error')` | `/about` | `qa.console_network_errors` |
| `<img>` without alt text, inputs without labels | `/`, `/contact` | `qa.accessibility` |
| Contact form POST fails with HTTP 500 | `/contact` | `qa.forms` |
| Checkout POST fails with HTTP 500 | `/checkout` | `qa.checkout` |
| Python stack trace shown to visitors (debug on) | `/checkout` (POST) | `security.error_leak` |
| No CSP, HSTS or X-Frame-Options | every page | `security.headers` |
| Cookie without Secure, HttpOnly, SameSite | every page | `security.cookies` |
| Session id in the URL (`?sid=`) | every nav link | `security.url_session_leak` |
| Open redirect | `/redirect?next=` | `security.open_redirect` |
| Reflected, unescaped input | `/search?q=` | `security.reflected_input` |
| Unauthenticated admin page | `/admin` | `security.exposed_endpoints` (the containment demo task) |
| No login rate limit or lockout | `/login` | `security.login_rate_probe` |
| Plain HTTP, no redirect to HTTPS | whole site | `security.https_redirect` |

Working pages (so QA checks have something that passes): `/products`, `/search` (UI), `/login` (demo user), `/password-reset`, `/cart`.
