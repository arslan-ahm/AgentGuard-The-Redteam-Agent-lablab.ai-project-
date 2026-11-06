# Sandbox worker

One container runs one scan task (brief 5.6 and 6.4).

- Input: `/in/task.json` (a `SandboxTaskInput`: `scan_id`, `target_url`, `task`)
- Output: `/out/result.json`, `console.json`, `network_summary.json`, `screenshots/*.png`
- Exit codes: `0` ok, `2` check error, `3` policy violation

`runner.py` only loads check ids on the whitelist in `agentguard_contracts.ALLOWED_CHECK_IDS`, runs the check under the task's `timeout_s`, and validates every finding against the contract. Anything that doesn't match is reported as `error`.

## Adding a check

Create `checks/<category>/<name>.py` for an id on the whitelist:

```python
from typing import Any
from checks.context import CheckContext

CHECK_ID = "security.headers"

async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
    ctx.policy.assert_allowed(ctx.target_url)      # before every navigation
    response = await page.goto(ctx.target_url)
    shot = await ctx.screenshot("headers_home")
    ctx.record_request({"url": ctx.target_url, "status": response.status})
    return []  # Finding dicts without id/scan_id (see FindingDraft)
```

Test checks with a fake page and a fake `ctx` (see `tests/test_runner.py`). Unit tests never hit real sites.

## Security checks (Arslan)

| Check id | What it does | Requests |
|---|---|---|
| `security.headers` | Missing CSP, HSTS (https only), `X-Content-Type-Options`, clickjacking protection, `Referrer-Policy`; `'unsafe-inline'` scripts; short HSTS; version numbers in `Server`/`X-Powered-By` | 1 GET |
| `security.cookies` | `Secure` (https), `HttpOnly` (session-like names), `SameSite` missing or `None` without `Secure`. Parses raw `Set-Cookie`; **values are never recorded** | 1 GET |
| `security.https_redirect` | http must 301/308 to https on the same host; an http-only target with no working TLS is `high`. Never follows redirects; skipped on non-default ports | ≤ 2 GETs |
| `security.error_leak` | Stack traces (Python, Node, Java, PHP, .NET, Django, Rails, Werkzeug) and SQL errors on any status; internal paths and server versions on error statuses only | 3 GETs: the page, `/<marker>`, `?id=<marker>` |

`params.path` (same-origin path only) picks the page; `params.probe_marker` sets the marked probe value (default `agentguard-probe-<random>`). Evidence never includes `Set-Cookie`, `Authorization` or other non-whitelisted headers (`checks/security/_common.py:EVIDENCE_HEADERS`).

## Network guard (Arslan)

`checks/netguard.py` is installed on every page by `runner.py` (`page.route("**/*")` + `page.route_web_socket`), in a browser context with service workers blocked. For **every** request it:

1. blocks before anything is sent: non-http(s) schemes, credentials in URLs, internal hostnames (`localhost`, `*.internal`, `host.docker.internal`, metadata names), private/loopback/link-local/metadata IPs, literal or after DNS (once per host per task);
2. follows redirects itself with `max_redirects=0`, checking each hop before requesting it. Chromium follows navigation redirects without calling `page.route` again (measured: `continue_()` let `302 -> 127.0.0.2/internal` through), so the guard never hands a 3xx back to the browser;
3. allows top-level navigations only within the target origin.

A blocked navigation is a `navigate`/`blocked` event: the task becomes `blocked`, exit 3, sandbox destroyed. A blocked subresource (an `<img>`, script or WebSocket pointing inside) is aborted and recorded as `subresource_blocked`. The request never left, so the task carries on.

The real-browser test is opt-in: `AGENTGUARD_LIVE_BROWSER=1 uv run pytest tests/test_netguard.py -k live` (needs `uv run playwright install chromium --only-shell`).

## Policy placeholder

`checks/context.py:SameOriginPolicy` allows only the target's own host and port. The one exception is switching between http and https on the same host when both use default ports, which `security.https_redirect` needs. It is a strict placeholder. Arslan replaces it with the full policy (DNS resolution, private/loopback/link-local/metadata blocking). The real boundary is the container's network egress rules, enforced by the launcher.

## Run

```bash
uv sync && uv run pytest
docker compose build sandbox     # from the repo root
```
