"""security.headers: missing or weak HTTP security headers (brief 3, 6.6).

One GET of the target page (``params.path`` optional). Read-only, no probes.
"""

from __future__ import annotations

import re
from typing import Any

from checks.context import CheckContext
from checks.security._common import (
    NETWORK_SUMMARY,
    finding,
    navigate,
    screenshot_or_none,
    target_path_url,
)

CHECK_ID = "security.headers"

_VERSION = re.compile(r"\d+\.\d+")


def analyse(url: str, headers: dict[str, str], evidence: list[str]) -> list[dict[str, Any]]:
    """Pure analysis of one response's headers (lower-cased names). Returns findings."""
    h = {k.lower(): v for k, v in headers.items()}
    https = url.lower().startswith("https://")
    found: list[dict[str, Any]] = []

    def add(title: str, severity: str, impact: str, fix: str, header: str) -> None:
        found.append(
            finding(
                check_id=CHECK_ID,
                title=title,
                severity=severity,
                url=url,
                evidence=evidence,
                reproduction=[
                    f"Request {url}",
                    f"Inspect the response headers: {header}",
                ],
                impact=impact,
                recommended_fix=fix,
            )
        )

    csp = h.get("content-security-policy", "")
    if not csp:
        add(
            "Missing Content-Security-Policy header",
            "medium",
            "No browser-enforced limit on where scripts can load from, so any XSS bug is "
            "easier to exploit.",
            "Send a Content-Security-Policy, starting with default-src 'self' and tightening "
            "script-src; roll out with Content-Security-Policy-Report-Only first.",
            "Content-Security-Policy is absent",
        )
    elif re.search(r"script-src[^;]*'unsafe-inline'", csp) or (
        "script-src" not in csp and re.search(r"default-src[^;]*'unsafe-inline'", csp)
    ):
        add(
            "Content-Security-Policy allows inline scripts",
            "low",
            "'unsafe-inline' for scripts removes most of the XSS protection CSP provides.",
            "Remove 'unsafe-inline' from script-src; use nonces or hashes for inline scripts.",
            "Content-Security-Policy script-src contains 'unsafe-inline'",
        )

    if https:
        hsts = h.get("strict-transport-security", "")
        match = re.search(r"max-age\s*=\s*\"?(\d+)", hsts, re.IGNORECASE)
        if not hsts or not match:
            add(
                "Missing Strict-Transport-Security header",
                "medium",
                "Browsers may be downgraded to plain HTTP on first visit or by an attacker "
                "on the network.",
                "Send Strict-Transport-Security: max-age=31536000; includeSubDomains.",
                "Strict-Transport-Security is absent",
            )
        elif int(match.group(1)) < 15_552_000:  # 180 days
            add(
                "Strict-Transport-Security max-age is too short",
                "low",
                "A short HSTS lifetime leaves a window for HTTPS downgrade.",
                "Use max-age of at least 15552000 (180 days), ideally 31536000.",
                f"Strict-Transport-Security is {hsts!r}",
            )

    if h.get("x-content-type-options", "").strip().lower() != "nosniff":
        add(
            "Missing X-Content-Type-Options: nosniff",
            "medium",
            "Browsers may MIME-sniff responses and execute uploaded or user content as script.",
            "Send X-Content-Type-Options: nosniff on every response.",
            "X-Content-Type-Options is absent or not 'nosniff'",
        )

    xfo = h.get("x-frame-options", "").strip().lower()
    if xfo not in ("deny", "sameorigin") and "frame-ancestors" not in csp:
        add(
            "Missing clickjacking protection",
            "medium",
            "The page can be framed by another site and used for clickjacking.",
            "Send Content-Security-Policy: frame-ancestors 'self' (or X-Frame-Options: DENY).",
            "neither X-Frame-Options nor CSP frame-ancestors is set",
        )

    if not h.get("referrer-policy"):
        add(
            "Missing Referrer-Policy header",
            "low",
            "Full URLs, including paths and query strings, may leak to third parties.",
            "Send Referrer-Policy: strict-origin-when-cross-origin.",
            "Referrer-Policy is absent",
        )

    disclosed = [
        f"{name}: {h[name]}"
        for name in ("server", "x-powered-by")
        if _VERSION.search(h.get(name, ""))
    ]
    if disclosed:
        add(
            "Server software version disclosed in headers",
            "low",
            "Exact versions help attackers pick known exploits.",
            "Remove version numbers from Server and X-Powered-By (or drop the headers).",
            "; ".join(disclosed)[:300],
        )
    return found


async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
    """Load the page once and analyse its response headers."""
    url = target_path_url(ctx)
    response = await navigate(page, ctx, url)
    if response is None:
        return []
    headers = await response.all_headers()
    evidence = [*await screenshot_or_none(ctx, "headers_page"), NETWORK_SUMMARY]
    return analyse(url, headers, evidence)
