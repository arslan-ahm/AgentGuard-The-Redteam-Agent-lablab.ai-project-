"""qa.pages_load: do the key pages load, and load in reasonable time? (brief 3, 6.5)

Opens the target (or ``params.path``, or up to 5 ``params.paths``) and reports pages that fail
to load, answer 404 or 5xx, have no ``<title>``, or take longer than ``SLOW_MS``.
Read-only: GET navigations on the target origin, nothing is submitted.
"""

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urljoin

from checks.context import CheckContext
from checks.qa._common import qa_finding, response_body, safe_navigate
from checks.security._common import NETWORK_SUMMARY, path_of, screenshot_or_none, target_path_url

CHECK_ID = "qa.pages_load"

_clock = time.monotonic  # a module-level reference so tests can fake load times
MAX_PAGES = 5
SLOW_MS = 8_000
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def page_urls(ctx: CheckContext) -> list[str]:
    """Pages to open: ``params.paths`` (max 5, same origin) or the single target/path URL."""
    paths = ctx.params.get("paths")
    if isinstance(paths, list):
        urls = [
            urljoin(ctx.target_url, p)
            for p in paths
            if isinstance(p, str) and p.startswith("/") and not p.startswith("//")
        ]
        if urls:
            return list(dict.fromkeys(urls))[:MAX_PAGES]
    return [target_path_url(ctx)]


def analyse(
    url: str, status: int, load_ms: int, body: str, evidence: list[str]
) -> list[dict[str, Any]]:
    """Findings for one loaded page."""
    path = path_of(url)
    found: list[dict[str, Any]] = []
    if status >= 500:
        found.append(
            qa_finding(
                check_id=CHECK_ID,
                title=f"Page {path} returns HTTP {status}",
                severity="high",
                url=url,
                evidence=evidence,
                reproduction=[f"Open {path}", f"Observe HTTP {status} instead of the page"],
                impact="Visitors see an error instead of the page, so they cannot use the site.",
                recommended_fix="Check the server logs for this route, fix the failing handler "
                "and add a monitor on the page.",
            )
        )
    elif status in (404, 410):
        found.append(
            qa_finding(
                check_id=CHECK_ID,
                title=f"Page {path} returns HTTP {status}",
                severity="medium",
                url=url,
                evidence=evidence,
                reproduction=[f"Open {path}", f"Observe HTTP {status} (page not found)"],
                impact="A page that should exist is missing, which breaks links and navigation.",
                recommended_fix="Restore the page or redirect it to its new location, and "
                "update links that point to it.",
            )
        )
    elif status < 400:
        title = _TITLE.search(body[:200_000])
        if not title or not " ".join(title.group(1).split()):
            found.append(
                qa_finding(
                    check_id=CHECK_ID,
                    title=f"Page {path} has no title",
                    severity="low",
                    url=url,
                    evidence=evidence,
                    reproduction=[f"Open {path}", "Look at the browser tab: no <title> is set"],
                    impact="Tabs, bookmarks, search results and screen readers show no page name.",
                    recommended_fix="Add a short, unique <title> to every page.",
                    confidence=0.85,
                )
            )
        if load_ms > SLOW_MS:
            found.append(
                qa_finding(
                    check_id=CHECK_ID,
                    title=f"Page {path} loads slowly ({load_ms / 1000:.1f}s)",
                    severity="low",
                    url=url,
                    evidence=evidence,
                    reproduction=[f"Open {path}", f"Observe {load_ms / 1000:.1f}s until it loads"],
                    impact="Slow pages lose visitors and hurt search ranking.",
                    recommended_fix="Profile the request, cache or trim heavy responses and "
                    "defer non-critical scripts.",
                    confidence=0.7,
                )
            )
    return found


async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
    """Open each page and report load problems."""
    found: list[dict[str, Any]] = []
    for n, url in enumerate(page_urls(ctx)):
        started = _clock()
        response = await safe_navigate(page, ctx, url)
        load_ms = int((_clock() - started) * 1000)
        shots = await screenshot_or_none(ctx, f"pages_load_{n}")
        evidence = [*shots, NETWORK_SUMMARY]
        if response is None:
            path = path_of(url)
            found.append(
                qa_finding(
                    check_id=CHECK_ID,
                    title=f"Page {path} failed to load",
                    severity="high",
                    url=url,
                    evidence=evidence,
                    reproduction=[f"Open {path}", "Observe a timeout or connection error"],
                    impact="Visitors cannot reach the page at all.",
                    recommended_fix="Check that the server is up, the route exists and the "
                    "response is not hanging.",
                    confidence=0.8,
                )
            )
            continue
        body = await response_body(response)
        found.extend(analyse(url, response.status, load_ms, body, evidence))
    return found
