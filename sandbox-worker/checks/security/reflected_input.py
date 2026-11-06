"""security.reflected_input: query input echoed into HTML without escaping (brief 3, 6.6).

The probe value is a marked, inert string: ``agentguard-probe-<id>"'<agentguard-probe-<id>>``.
It contains no script and no event handler; it only shows whether ``<``, ``>`` and quotes come
back unescaped (the precondition for reflected XSS). Responses are fetched with the API
client, never rendered, so nothing in them runs. GET only, at most ``MAX_PROBES`` requests.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qsl, urlsplit

from checks.context import CheckContext
from checks.security._common import (
    NETWORK_SUMMARY,
    fetch,
    finding,
    navigate,
    page_forms,
    page_links,
    path_of,
    probe_marker,
    same_origin,
    snippet,
    target_path_url,
    with_param,
)

CHECK_ID = "security.reflected_input"

MAX_PROBES = 6
DEFAULT_PARAMS = ("q", "search", "query", "s")
TEXT_INPUTS = frozenset({"text", "search", "email", "url", "tel", "input", "textarea", ""})


def probe_value(marker: str) -> tuple[str, str]:
    """``(value to send, tag that proves unescaped reflection)``."""
    tag = f"<{marker.lower()}>"
    return f"{marker}\"'{tag}", tag


def candidates(
    ctx: CheckContext, links: list[str], forms: list[dict[str, Any]]
) -> list[tuple[str, str]]:
    """``(page_url, param)`` pairs: GET form text fields, then same-origin link parameters,
    then common search parameter names on the target page."""
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []

    def add(url: str, param: str) -> None:
        key = (urlsplit(url).path or "/", param)
        if param and key not in seen and len(out) < MAX_PROBES:
            seen.add(key)
            out.append((url, param))

    for form in forms:
        action = str(form.get("action") or "")
        if form.get("method", "get") != "get" or not same_origin(action, ctx.target_url):
            continue
        for field in form.get("inputs") or []:
            if isinstance(field, dict) and str(field.get("type", "")) in TEXT_INPUTS:
                add(action, str(field.get("name") or ""))
    for link in links:
        if same_origin(link, ctx.target_url):
            for name, _ in parse_qsl(urlsplit(link).query, keep_blank_values=True):
                add(link, name)
    for name in DEFAULT_PARAMS:
        add(target_path_url(ctx), name)
    return out


def _is_html(content_type: str) -> bool:
    ct = content_type.lower()
    return not ct or "html" in ct


async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
    """Send the marked value in each candidate parameter; report the first unescaped echo."""
    marker = probe_marker(ctx)
    value, tag = probe_value(marker)
    await navigate(page, ctx, target_path_url(ctx))
    pairs = candidates(ctx, await page_links(page), await page_forms(page))

    for page_url, param in pairs:
        url = with_param(page_url, param, value)
        got = await fetch(page, ctx, url)
        if got is None or not _is_html(got.headers.get("content-type", "")):
            continue
        at = got.body.lower().find(tag)
        if at < 0:
            continue  # absent, or escaped (&lt;...&gt;): safe
        excerpt = snippet(got.body, at, at + len(tag), radius=80)
        ctx.record_request({"url": url, "reflected_param": param, "excerpt": excerpt})
        return [
            finding(
                check_id=CHECK_ID,
                title=f"Input reflected without HTML escaping ({param!r} parameter)",
                severity="high",
                url=url,
                evidence=[NETWORK_SUMMARY],
                reproduction=[
                    f"Request {path_of(url)}",
                    f"Observe the raw tag {tag} in the HTTP {got.status} response instead of "
                    f"&lt;{marker.lower()}&gt;",
                ],
                impact="Markup from the URL is inserted into the page as-is, so a crafted "
                "link can run attacker script in a victim's session (reflected XSS).",
                recommended_fix="HTML-escape all user input on output (use the template "
                "engine's auto-escaping), validate input, and add a strict "
                "Content-Security-Policy.",
                confidence=0.85,
            )
        ]
    return []
