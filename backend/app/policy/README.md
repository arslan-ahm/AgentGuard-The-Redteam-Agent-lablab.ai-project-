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

## Tests

```bash
cd backend && uv run pytest tests/test_policy_url.py
```

No network: DNS is a fake resolver and HTTP is `httpx.MockTransport`.
