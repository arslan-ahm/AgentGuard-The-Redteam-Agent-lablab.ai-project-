# Policy + audit (brief 6.9)

Owner: Arslan · Reviewer: Sarah

## URL policy (`url_policy.py`)

`UrlValidator` implements `app.interfaces.UrlPolicy`.

```python
from app.policy.url_policy import PolicyBlocked, UrlValidator

validator = UrlValidator()                       # real DNS (getaddrinfo), 3 s timeout
try:
    target = await validator.resolve_allowed(body.target_url)
except PolicyBlocked as exc:
    ...  # 422 + audit event {actor: "policy", decision: "blocked", reason: exc.reason}
target.addresses   # IPs that were checked: the launcher pins these (--add-host)
```

A URL is blocked when any of these is true:

| Rule | Examples |
|---|---|
| Scheme is not http/https | `file:`, `javascript:`, `ftp:`, scheme-relative `//host` |
| Credentials in the URL | `https://user:pw@host`, `https://host@169.254.169.254` |
| Malformed, too long, control characters or backslashes | `:99999`, `\r\n`, `host\@evil` |
| Internal hostname | `localhost`, `*.localhost`, `*.local`, `*.internal`, `metadata.google.internal`, single-label names like `postgres` |
| **Any** resolved address is not public | loopback, RFC1918, CGNAT, link-local, `169.254.169.254`, multicast, reserved, ULA, and IPv4 hidden in IPv6 (mapped, 6to4, Teredo, NAT64) |
| IPv4 shorthand that resolves to the above | `127.1`, `0x7f000001`, `2130706433`, `0177.0.0.1` |

Redirects: `follow_redirects_safely(url, validator, client)` follows them one hop at a time and validates each hop **before** requesting it (max 5). Each call re-resolves DNS with no caching, so a name that rebinds to a private address is caught on the next check.

This is one layer. The sandbox's egress rules (launcher, brief 6.4) block private ranges no matter what DNS says.

## Secret redaction (`redaction.py`)

```python
from app.policy.redaction import redact, redact_headers, redact_text

redact_text("GET /reset?token=abc123")   # "GET /reset?token=[REDACTED]"
redact({"headers": {"Cookie": "sid=x"}})  # {"headers": {"Cookie": "[REDACTED]"}}
```

- `redact(value)` returns a deep copy. The value of any key that names a secret (`password`, `token`, `authorization`, `cookie`, `api_key`, `session_id`, `db_password`, `githubToken`...) becomes `[REDACTED]`, and every other string goes through `redact_text`.
- `redact_text` catches bearer/basic credentials, `Authorization`/`Cookie`/`Set-Cookie` values, JWTs, PEM private keys, AWS/GitHub/OpenAI/Anthropic/Stripe/Slack/Google/Supabase keys, `user:pass@` in URLs, secret query parameters (`token`, `code`, `sig`, `X-Amz-Signature`...) and `password=`/`"password": "..."` pairs.
- Names are kept and only values are replaced, so evidence still says *what* leaked. Every pattern is bounded, so hostile input is redacted in linear time (tested).
- The launcher applies it to everything the sandbox returns before anything else reads it: `network_summary.json` and `console.json` are rewritten in place (unparseable files become `[]`), and finding title/url/reproduction/impact plus `policy_events` are redacted. Redaction never changes a result's status.

## Audit log (`audit.py`)

`HashChainedAuditLog(store)` implements `app.interfaces.AuditSink`.

```python
from app.policy.audit import HashChainedAuditLog, JsonlAuditStore

audit = HashChainedAuditLog(JsonlAuditStore(Path("/data/audit/audit.jsonl")))
await audit.append(event)            # target/reason redacted, then chained
await audit.events(scan_id)          # for GET /scans/{id}/audit
ok, first_bad_seq = await audit.verify()
```

- Each record stores `hash = sha256(prev_hash + "\n" + canonical_json(event))`. Editing, deleting, inserting or reordering any record breaks the chain, and `verify()` returns the first bad `seq`. There is no update or delete API.
- `JsonlAuditStore` holds an exclusive OS file lock (`fcntl.flock` / `msvcrt.locking`) while it reads the last record and appends the next, and `fsync`s, so the API and worker processes can share one file (tested with 4 processes).
- A torn last line (a crash mid-write) makes later appends fail loudly instead of starting a new chain. Fix it by hand; the chain before it still verifies.
- `InMemoryAuditStore` is for tests. A DB store only needs the same two methods and a role with INSERT/SELECT only.
- `target` and `reason` are capped at 2000 characters.

## Rate limits (`rate_limit.py`)

```python
from app.policy.rate_limit import ScanRateLimiter

limiter = ScanRateLimiter()           # 10 scans/user/hour, 6 scans/target host/hour
decision = await limiter.check(user_id, body.target_url)
if not decision.allowed:
    ...  # 429, Retry-After: decision.retry_after_s, reason: decision.reason
```

Sliding windows, in memory, per process. The target key is the lowercased host without port or trailing dot, so `SHOP.example.com:8080` and `shop.example.com.` share a quota. Refused requests don't use up quota, and idle keys are dropped.

## Wiring (not done here)

These are building blocks. Hooking `HashChainedAuditLog` and `ScanRateLimiter` into the API's dependencies is in the API module (Sohaib).

## Tests

```bash
cd backend && uv run pytest tests/test_policy_url.py tests/test_policy_redaction.py tests/test_policy_audit.py tests/test_policy_rate_limit.py
```

No network: DNS is a fake resolver, HTTP is `httpx.MockTransport`, time is a fake clock.
