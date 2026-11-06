"""Shared helpers for security checks. Not a check module (no CHECK_ID), never loaded by id."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

from checks.context import CheckContext

REQUEST_TIMEOUT_MS = 15_000
MAX_BODY_CHARS = 200_000
NETWORK_SUMMARY = "network_summary.json"

# Response headers that are safe to copy into evidence. Everything else (Set-Cookie,
# Authorization, custom tokens...) is left out so evidence never carries secrets.
EVIDENCE_HEADERS = frozenset(
    {
        "content-type",
        "content-security-policy",
        "content-security-policy-report-only",
        "strict-transport-security",
        "x-content-type-options",
        "x-frame-options",
        "referrer-policy",
        "permissions-policy",
        "location",
        "server",
        "x-powered-by",
    }
)


def finding(
    *,
    check_id: str,
    title: str,
    severity: str,
    url: str,
    evidence: list[str],
    reproduction: list[str],
    impact: str,
    recommended_fix: str,
    confidence: float = 0.95,
) -> dict[str, Any]:
    """A Finding dict (brief 5.4 without id/scan_id). ``verified`` is left to the Verifier."""
    return {
        "title": title,
        "category": "security",
        "severity": severity,
        "confidence": confidence,
        "url": url,
        "evidence": evidence,
        "reproduction": reproduction,
        "impact": impact,
        "recommended_fix": recommended_fix,
        "check_id": check_id,
    }


def evidence_headers(headers: dict[str, str]) -> dict[str, str]:
    """Only the whitelisted, non-secret headers, truncated."""
    return {k: v[:500] for k, v in headers.items() if k.lower() in EVIDENCE_HEADERS}


def target_path_url(ctx: CheckContext) -> str:
    """``target_url`` joined with ``params.path`` (if any), keeping the target's origin."""
    path = ctx.params.get("path")
    if isinstance(path, str) and path.startswith("/") and not path.startswith("//"):
        return urljoin(ctx.target_url, path)
    return ctx.target_url


def with_path(url: str, path: str) -> str:
    """Same scheme://host:port, new path, no query or fragment."""
    parts = urlsplit(url)
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def path_of(url: str) -> str:
    parts = urlsplit(url)
    return (parts.path or "/") + (f"?{parts.query}" if parts.query else "")


async def navigate(page: Any, ctx: CheckContext, url: str) -> Any:
    """Policy check, then ``page.goto``. Records status and safe headers. Returns the response."""
    ctx.policy.assert_allowed(url)
    response = await page.goto(url, timeout=REQUEST_TIMEOUT_MS, wait_until="domcontentloaded")
    if response is None:
        ctx.record_request({"url": url, "status": None})
        return None
    headers = await response.all_headers()
    ctx.record_request(
        {"url": url, "status": response.status, "headers": evidence_headers(headers)}
    )
    return response


async def screenshot_or_none(ctx: CheckContext, name: str) -> list[str]:
    """Screenshot filename in a list, or an empty list if the page can't be captured."""
    try:
        return [await ctx.screenshot(name)]
    except Exception:  # evidence is best-effort; the finding stands on network evidence
        return []


_SAFE_SNIPPET = re.compile(r"[^\x20-\x7e\n]")


def snippet(text: str, start: int, end: int, radius: int = 120) -> str:
    """Printable excerpt around a match, for evidence (never the whole body)."""
    lo, hi = max(0, start - radius), min(len(text), end + radius)
    return _SAFE_SNIPPET.sub("?", text[lo:hi])
