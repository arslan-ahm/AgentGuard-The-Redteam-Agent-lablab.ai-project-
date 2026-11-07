"""qa.console_network_errors: JavaScript errors and failing requests on a page (brief 3, 6.5).

Opens the page (``params.path`` or the target) while listening to the browser console, uncaught
page errors, failed requests and HTTP 4xx/5xx responses. Only same-origin requests count (the
network guard aborts everything else, which is containment working, not a bug). Console text
is truncated and masked for anything that looks like a token or password, and URLs lose their
query string before they reach the evidence.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from checks.context import CheckContext
from checks.qa._common import qa_finding, redact, safe_navigate
from checks.security._common import (
    NETWORK_SUMMARY,
    path_of,
    same_origin,
    screenshot_or_none,
    target_path_url,
)

CHECK_ID = "qa.console_network_errors"

MAX_ITEMS = 50
SETTLE_MS = 3_000
_IGNORED_PATHS = frozenset({"/favicon.ico", "/apple-touch-icon.png"})


def strip_query(url: str) -> str:
    """``url`` without query string or fragment (they may carry tokens)."""
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


def _unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _summary(items: list[str], limit: int = 3) -> str:
    shown = "; ".join(items[:limit])
    return shown + (f" (+{len(items) - limit} more)" if len(items) > limit else "")


async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
    """Load the page, collect console and network problems, report each kind once."""
    url = target_path_url(ctx)
    errors: list[str] = []
    warnings: list[str] = []
    page_errors: list[str] = []
    failed: list[str] = []

    def on_console(msg: Any) -> None:
        text = redact(str(msg.text))
        if msg.type == "error" and len(errors) < MAX_ITEMS:
            errors.append(text)
        elif msg.type == "warning" and len(warnings) < MAX_ITEMS:
            warnings.append(text)

    def on_page_error(exc: Any) -> None:
        if len(page_errors) < MAX_ITEMS:
            page_errors.append(redact(str(getattr(exc, "message", None) or exc)))

    def counts(request_url: str) -> bool:
        return (
            same_origin(request_url, ctx.target_url)
            and strip_query(request_url) != strip_query(url)
            and urlsplit(request_url).path not in _IGNORED_PATHS
        )

    def on_request_failed(request: Any) -> None:
        if counts(request.url) and len(failed) < MAX_ITEMS:
            failed.append(f"{strip_query(request.url)} ({redact(str(request.failure), 80)})")

    def on_response(response: Any) -> None:
        if response.status >= 400 and counts(response.url) and len(failed) < MAX_ITEMS:
            failed.append(f"{strip_query(response.url)} (HTTP {response.status})")

    handlers = {
        "console": on_console,
        "pageerror": on_page_error,
        "requestfailed": on_request_failed,
        "response": on_response,
    }
    for event, handler in handlers.items():
        page.on(event, handler)
    try:
        if await safe_navigate(page, ctx, url) is None:
            return []
        try:
            await page.wait_for_load_state("networkidle", timeout=SETTLE_MS)
        except Exception:  # pages that never go idle (polling, streaming) are fine
            ctx.record_request({"url": url, "note": "network never went idle"})
    finally:
        for event, handler in handlers.items():
            page.remove_listener(event, handler)

    for kind, items in (
        ("pageerror", page_errors),
        ("console.error", errors),
        ("console.warning", warnings),
        ("failed_request", failed),
    ):
        for item in _unique(items):
            ctx.record_request({"url": strip_query(url), kind: item})

    shots = await screenshot_or_none(ctx, "console_network_errors")
    evidence = [*shots, NETWORK_SUMMARY]
    path = path_of(strip_query(url))
    found: list[dict[str, Any]] = []

    if page_errors:
        uniq = _unique(page_errors)
        found.append(
            qa_finding(
                check_id=CHECK_ID,
                title=f"Uncaught JavaScript error on {path}",
                severity="medium",
                url=url,
                evidence=evidence,
                reproduction=[f"Open {path}", f"Open the browser console: {_summary(uniq)}"],
                impact="Broken scripts can disable buttons, forms or whole sections of the page.",
                recommended_fix="Fix the exception, add error boundaries, and report front-end "
                "errors to a monitoring service.",
            )
        )
    if errors:
        uniq = _unique(errors)
        found.append(
            qa_finding(
                check_id=CHECK_ID,
                title=f"Console errors on {path} ({len(uniq)})",
                severity="medium",
                url=url,
                evidence=evidence,
                reproduction=[f"Open {path}", f"Open the browser console: {_summary(uniq)}"],
                impact="Errors in the console usually mean a feature or resource is failing.",
                recommended_fix="Fix the cause of each error; keep the console clean in "
                "production.",
                confidence=0.85,
            )
        )
    if failed:
        uniq = _unique(failed)
        found.append(
            qa_finding(
                check_id=CHECK_ID,
                title=f"{len(uniq)} failing request(s) on {path}",
                severity="medium",
                url=url,
                evidence=evidence,
                reproduction=[f"Open {path}", f"Watch the network tab: {_summary(uniq)}"],
                impact="Missing scripts, styles, images or API calls leave the page broken.",
                recommended_fix="Fix or remove each failing URL and monitor 4xx/5xx rates.",
                confidence=0.9,
            )
        )
    if warnings:
        uniq = _unique(warnings)
        found.append(
            qa_finding(
                check_id=CHECK_ID,
                title=f"Console warnings on {path} ({len(uniq)})",
                severity="low",
                url=url,
                evidence=evidence,
                reproduction=[f"Open {path}", f"Open the browser console: {_summary(uniq)}"],
                impact="Warnings often point at deprecated or fragile code.",
                recommended_fix="Resolve the warnings during the next maintenance pass.",
                confidence=0.7,
            )
        )
    return found
