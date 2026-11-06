"""security.open_redirect: redirect parameters that send visitors to any site (brief 3, 6.6).

The probe value is a clearly marked address on the reserved ``.invalid`` TLD
(``https://agentguard-probe-<id>.invalid/``), which can never resolve. Each probe is a single
GET with redirects **not** followed, so the check never leaves the target origin; only the
``Location`` header (or a meta refresh) is inspected. At most ``MAX_PROBES`` requests.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from checks.context import CheckContext
from checks.security._common import (
    NETWORK_SUMMARY,
    fetch,
    finding,
    navigate,
    page_links,
    path_of,
    probe_marker,
    same_origin,
    target_path_url,
    with_param,
)

CHECK_ID = "security.open_redirect"

MAX_PROBES = 8
REDIRECT_PARAMS = frozenset(
    {
        "next",
        "url",
        "redirect",
        "redirect_uri",
        "redirect_url",
        "redirect_to",
        "redirectto",
        "return",
        "return_to",
        "returnto",
        "returnurl",
        "return_url",
        "continue",
        "dest",
        "destination",
        "goto",
        "target",
        "redir",
        "forward",
        "callback",
    }
)
DEFAULT_PARAMS = ("next", "redirect", "url", "return_to")
"""Tried on the target page when no link on it already uses a redirect parameter."""


def probe_host(marker: str) -> str:
    return f"{marker.lower()[:40]}.invalid"


def candidates(ctx: CheckContext, links: list[str]) -> list[tuple[str, str]]:
    """``(page_url, param)`` pairs to probe: redirect parameters found in same-origin links
    first, then the defaults on the target page. Deduplicated by (path, param)."""
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []

    def add(url: str, param: str) -> None:
        key = (urlsplit(url).path or "/", param.lower())
        if key not in seen and len(out) < MAX_PROBES:
            seen.add(key)
            out.append((url, param))

    for link in links:
        if not same_origin(link, ctx.target_url):
            continue
        for name, _ in parse_qsl(urlsplit(link).query, keep_blank_values=True):
            if name.lower() in REDIRECT_PARAMS:
                add(link, name)
    page_url = target_path_url(ctx)
    for name in DEFAULT_PARAMS:
        add(page_url, name)
    return out


def _meta_refresh_to(body: str, host: str) -> bool:
    pattern = re.compile(
        r"<meta[^>]{0,300}http-equiv\s*=\s*[\"']?refresh[^>]{0,500}" + re.escape(host),
        re.IGNORECASE,
    )
    return bool(pattern.search(body[:200_000]))


async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
    """Probe each candidate parameter with the marked external URL."""
    marker = probe_marker(ctx)
    host = probe_host(marker)
    probe_value = f"https://{host}/"
    await navigate(page, ctx, target_path_url(ctx))
    links = await page_links(page)

    for page_url, param in candidates(ctx, links):
        url = with_param(page_url, param, probe_value)
        got = await fetch(page, ctx, url)
        if got is None:
            continue
        via = ""
        if 300 <= got.status < 400 and urlsplit(got.location).hostname == host:
            via = f"HTTP {got.status} with Location: {got.location}"
        elif got.status == 200 and _meta_refresh_to(got.body, host):
            via = "a <meta http-equiv=refresh> pointing to it"
        if not via:
            continue
        ctx.record_request({"url": url, "open_redirect": param, "observed": via})
        # One confirmed open redirect is enough evidence; stop probing.
        return [
            finding(
                check_id=CHECK_ID,
                title=f"Open redirect via the {param!r} parameter",
                severity="medium",
                url=url,
                evidence=[NETWORK_SUMMARY],
                reproduction=[
                    f"Request {path_of(url)} without following redirects",
                    f"Observe {via} (a reserved, unresolvable test domain)",
                ],
                impact="Attackers can send links on your domain that land on their own "
                "site, which makes phishing and OAuth token theft far more convincing.",
                recommended_fix="Only redirect to relative paths or to an allow-list of your "
                "own hosts; reject absolute and protocol-relative (//host) URLs.",
                confidence=0.9 if via.startswith("HTTP") else 0.8,
            )
        ]
    return []
