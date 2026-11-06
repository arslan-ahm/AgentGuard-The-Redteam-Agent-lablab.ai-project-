"""qa.search: does the site search answer without errors? (brief 3, 6.5)

Finds the search form on the page (a GET form with a ``search``-type input or a field named
``q``, ``query``, ``s``, ``search``, ``keyword`` or ``term``) and runs it twice: with a marked
harmless term (``agentguard-probe-<id>``) and with an empty query. Plain GETs on the target
origin, redirects not followed.
"""

from __future__ import annotations

from typing import Any

from checks.context import CheckContext
from checks.qa._common import named_inputs, qa_finding, safe_navigate
from checks.security._common import (
    NETWORK_SUMMARY,
    fetch,
    page_forms,
    path_of,
    probe_marker,
    same_origin,
    screenshot_or_none,
    target_path_url,
    with_param,
)

CHECK_ID = "qa.search"

_SEARCH_NAMES = frozenset({"q", "query", "s", "search", "keyword", "keywords", "term"})


def search_form(forms: list[dict[str, Any]], target_url: str) -> tuple[dict[str, Any], str] | None:
    """``(form, field name)`` of the first same-origin GET search form."""
    for form in forms:
        if form.get("method") != "get" or not same_origin(
            str(form.get("action") or ""), target_url
        ):
            continue
        for item in named_inputs(form):
            name = str(item["name"])
            if item.get("type") == "search" or name.lower() in _SEARCH_NAMES:
                return form, name
    return None


async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
    """Search for a marked term and for nothing; report server errors."""
    page_url = target_path_url(ctx)
    if await safe_navigate(page, ctx, page_url) is None:
        return []
    hit = search_form(await page_forms(page), ctx.target_url)
    if hit is None:
        ctx.record_request({"url": page_url, "skipped": "no search form found"})
        return []
    form, field = hit
    action = str(form["action"])
    shots = await screenshot_or_none(ctx, "search")
    evidence = [*shots, NETWORK_SUMMARY]
    origin = path_of(page_url)
    marker = probe_marker(ctx)

    found: list[dict[str, Any]] = []
    term = await fetch(page, ctx, with_param(action, field, marker))
    if term is not None and term.status >= 500:
        found.append(
            qa_finding(
                check_id=CHECK_ID,
                title=f"Search fails with HTTP {term.status}",
                severity="high",
                url=with_param(action, field, marker),
                evidence=evidence,
                reproduction=[
                    f"Open {origin}",
                    f"Search for '{marker}'",
                    f"Observe HTTP {term.status} instead of a results page",
                ],
                impact="Visitors cannot find products or content, which costs sales.",
                recommended_fix="Check the server log for the search handler and make a query "
                "with no matches return an empty results page.",
            )
        )
        return found

    empty = await fetch(page, ctx, with_param(action, field, ""))
    if empty is not None and empty.status >= 500:
        found.append(
            qa_finding(
                check_id=CHECK_ID,
                title=f"Search crashes on an empty query (HTTP {empty.status})",
                severity="medium",
                url=with_param(action, field, ""),
                evidence=evidence,
                reproduction=[
                    f"Open {origin}",
                    "Submit the search form with nothing typed",
                    f"Observe HTTP {empty.status} instead of a prompt or all results",
                ],
                impact="An empty search is common; crashing on it shows visitors an error page.",
                recommended_fix="Treat an empty query as 'show everything' or ask for a term.",
                confidence=0.85,
            )
        )
    return found
