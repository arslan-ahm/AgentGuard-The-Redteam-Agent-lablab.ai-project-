"""Shared helpers for security checks. Not a check module (no CHECK_ID), never loaded by id."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from playwright.async_api import Error as PlaywrightError

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


def probe_marker(ctx: CheckContext) -> str:
    """Harmless, clearly marked test value (brief 3): ``agentguard-probe-<random>``, or
    ``params.probe_marker`` (letters, digits and dashes only, at most 40 characters)."""
    raw = str(ctx.params.get("probe_marker") or f"agentguard-probe-{secrets.token_hex(4)}")
    return re.sub(r"[^a-zA-Z0-9-]", "", raw)[:40].strip("-") or "agentguard-probe"


def origin_of(url: str) -> tuple[str, str, int | None]:
    """(scheme, lowercased host, port with default filled in). Never raises."""
    try:
        parts = urlsplit(url)
        port = parts.port or {"http": 80, "https": 443}.get(parts.scheme)
    except ValueError:
        return "", "", None
    return parts.scheme, (parts.hostname or "").lower(), port


def same_origin(url: str, target_url: str) -> bool:
    """True if ``url`` is on the target's own scheme, host and port."""
    mine = origin_of(url)
    return bool(mine[1]) and mine == origin_of(target_url)


def with_param(url: str, name: str, value: str) -> str:
    """``url`` with query parameter ``name`` set to ``value`` (other parameters kept)."""
    parts = urlsplit(url)
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != name]
    query.append((name, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", urlencode(query), ""))


@dataclass(frozen=True)
class Fetched:
    """A response read without following redirects."""

    url: str
    status: int
    headers: dict[str, str]
    body: str

    @property
    def location(self) -> str:
        """Absolute ``Location`` header, or ``""``."""
        loc = self.headers.get("location", "")
        return urljoin(self.url, loc) if loc else ""


async def fetch(
    page: Any,
    ctx: CheckContext,
    url: str,
    *,
    form: dict[str, str] | None = None,
) -> Fetched | None:
    """Policy check, then one GET (or form POST) that never follows redirects, so the check
    can't be bounced to a URL the policy never saw. None if the request failed."""
    ctx.policy.assert_allowed(url)
    method = "POST" if form is not None else "GET"
    try:
        if form is None:
            response = await page.request.get(url, max_redirects=0, timeout=REQUEST_TIMEOUT_MS)
        else:
            response = await page.request.post(
                url, form=form, max_redirects=0, timeout=REQUEST_TIMEOUT_MS
            )
    except PlaywrightError as exc:
        error = str(exc).splitlines()[0][:200] if str(exc) else type(exc).__name__
        ctx.record_request({"url": url, "method": method, "status": None, "error": error})
        return None
    headers = {k.lower(): v for k, v in response.headers.items()}
    try:
        body = (await response.text())[:MAX_BODY_CHARS]
    except Exception:  # binary or aborted body: nothing to scan
        body = ""
    ctx.record_request(
        {
            "url": url,
            "method": method,
            "status": response.status,
            "headers": evidence_headers(headers),
        }
    )
    return Fetched(url, response.status, headers, body)


_LINKS_JS = "els => els.slice(0, 500).map(e => e.href).filter(h => typeof h === 'string')"

_FORMS_JS = """forms => forms.slice(0, 20).map(f => ({
  action: new URL(f.getAttribute('action') || '', document.baseURI).href,
  method: (f.getAttribute('method') || 'get').toLowerCase(),
  inputs: Array.from(f.querySelectorAll('input, textarea, select')).slice(0, 50).map(i => ({
    name: i.getAttribute('name') || '',
    type: (i.getAttribute('type') || i.tagName).toLowerCase(),
    value: i.getAttribute('value') || ''
  }))
}))"""


async def page_links(page: Any) -> list[str]:
    """Absolute ``href`` of up to 500 links on the current page. Empty if unreadable."""
    try:
        links = await page.eval_on_selector_all("a[href]", _LINKS_JS)
    except Exception:  # detached page, CSP-blocked eval...: no links rather than a crash
        return []
    return [h for h in links if isinstance(h, str)][:500]


async def page_forms(page: Any) -> list[dict[str, Any]]:
    """Up to 20 forms on the current page: ``{action, method, inputs: [{name, type, value}]}``."""
    try:
        forms = await page.eval_on_selector_all("form", _FORMS_JS)
    except Exception:
        return []
    return [f for f in forms if isinstance(f, dict)][:20]


_SAFE_SNIPPET = re.compile(r"[^\x20-\x7e\n]")


def snippet(text: str, start: int, end: int, radius: int = 120) -> str:
    """Printable excerpt around a match, for evidence (never the whole body)."""
    lo, hi = max(0, start - radius), min(len(text), end + radius)
    return _SAFE_SNIPPET.sub("?", text[lo:hi])
