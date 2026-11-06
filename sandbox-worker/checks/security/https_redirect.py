"""security.https_redirect: plain HTTP must redirect to HTTPS (brief 3, 6.6).

At most two GETs without following redirects (``max_redirects=0``), so the check never leaves
the policy-approved URLs. Targets on a non-default port are skipped: http and https can't
share one port, and guessing other ports is out of scope.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urljoin, urlsplit

from playwright.async_api import Error as PlaywrightError

from checks.context import CheckContext
from checks.security._common import (
    NETWORK_SUMMARY,
    REQUEST_TIMEOUT_MS,
    evidence_headers,
    finding,
    with_path,
)

CHECK_ID = "security.https_redirect"


async def _probe(page: Any, ctx: CheckContext, url: str) -> tuple[int, str] | None:
    """GET without following redirects. ``(status, absolute Location)`` or None if unreachable."""
    ctx.policy.assert_allowed(url)
    try:
        response = await page.request.get(url, max_redirects=0, timeout=REQUEST_TIMEOUT_MS)
    except PlaywrightError as exc:
        ctx.record_request({"url": url, "status": None, "error": str(exc).splitlines()[0][:200]})
        return None
    headers: dict[str, str] = response.headers
    location = urljoin(url, headers.get("location", "")) if headers.get("location") else ""
    ctx.record_request(
        {"url": url, "status": response.status, "headers": evidence_headers(headers)}
    )
    return response.status, location


def _redirects_to_https(status: int, location: str, host: str) -> bool:
    parts = urlsplit(location)
    return 300 <= status < 400 and parts.scheme == "https" and parts.hostname == host


def _no_redirect(http_url: str, status: int, location: str) -> dict[str, Any]:
    observed = f"HTTP {status}" + (f" redirecting to {location}" if location else "")
    return finding(
        check_id=CHECK_ID,
        title="HTTP does not redirect to HTTPS",
        severity="medium",
        url=http_url,
        evidence=[NETWORK_SUMMARY],
        reproduction=[
            f"Request {http_url} without following redirects",
            f"Observe {observed} instead of a redirect to https://",
        ],
        impact="Visitors who type the address or follow an old link use an unencrypted "
        "connection that can be read or modified on the network.",
        recommended_fix="Redirect every http:// request to https:// with 301 (or 308) and "
        "add Strict-Transport-Security.",
    )


async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
    """Check that HTTP is redirected to HTTPS on the target host."""
    target = urlsplit(ctx.target_url)
    host = target.hostname or ""
    if target.port is not None and target.port != {"http": 80, "https": 443}[target.scheme]:
        ctx.record_request({"url": ctx.target_url, "skipped": "non-default port"})
        return []
    # Hostname only: an explicit default port (":443") must not leak into the http URL.
    authority = f"[{host}]" if ":" in host else host
    http_url = with_path(f"http://{authority}", "/")
    https_url = with_path(f"https://{authority}", "/")

    if target.scheme == "http":
        tls = await _probe(page, ctx, https_url)
        if tls is None:
            return [
                finding(
                    check_id=CHECK_ID,
                    title="Site is not available over HTTPS",
                    severity="high",
                    url=https_url,
                    evidence=[NETWORK_SUMMARY],
                    reproduction=[
                        f"Request {https_url}",
                        "Observe the connection or TLS handshake fails",
                    ],
                    impact="All traffic, including logins and form data, travels unencrypted.",
                    recommended_fix="Serve the site over HTTPS with a valid certificate (e.g. "
                    "Let's Encrypt via Caddy) and redirect HTTP to it.",
                )
            ]

    plain = await _probe(page, ctx, http_url)
    if plain is None:
        return []  # nothing served over plain HTTP: nothing to redirect
    status, location = plain
    if _redirects_to_https(status, location, host):
        return []
    if 200 <= status < 300 or 300 <= status < 400:
        return [_no_redirect(http_url, status, location)]
    return []  # 4xx/5xx over HTTP: no content served in clear text
