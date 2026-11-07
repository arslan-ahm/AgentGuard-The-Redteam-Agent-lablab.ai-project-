"""qa.links_assets: broken links and missing images, scripts and stylesheets (brief 3, 6.5).

Collects same-origin links and assets from the page and requests each with one GET (redirects
not followed). Only the target's own origin is touched; off-origin links are never requested.
Read-only.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urldefrag, urlsplit, urlunsplit

from checks.context import CheckContext
from checks.qa._common import qa_finding, safe_navigate
from checks.security._common import (
    NETWORK_SUMMARY,
    fetch,
    page_links,
    path_of,
    same_origin,
    screenshot_or_none,
    target_path_url,
)

CHECK_ID = "qa.links_assets"

MAX_REQUESTS = 40
MAX_FINDINGS = 6

_ASSET_SELECTOR = "img[src], script[src], link[rel~='stylesheet'][href]"
_ASSETS_JS = """els => els.slice(0, 300).map(e => ({
  tag: e.tagName.toLowerCase(),
  url: e.currentSrc || e.src || e.href || ''
})).filter(a => a.url)"""

_ASSET_LABEL = {"img": "image", "script": "script", "link": "stylesheet"}
_ASSET_SEVERITY = {"img": "low", "script": "medium", "link": "medium"}


async def page_assets(page: Any) -> list[dict[str, str]]:
    """``{tag, url}`` for images, scripts and stylesheets on the current page."""
    try:
        raw = await page.eval_on_selector_all(_ASSET_SELECTOR, _ASSETS_JS)
    except Exception:  # detached page or blocked eval: no assets rather than a crash
        return []
    return [
        {"tag": str(a["tag"]), "url": str(a["url"])}
        for a in raw
        if isinstance(a, dict) and a.get("tag") in _ASSET_LABEL and a.get("url")
    ][:300]


def _normalise(url: str) -> str:
    """Drop the fragment and give an empty path its ``/`` so the same page compares equal."""
    parts = urlsplit(urldefrag(url).url)
    return urlunsplit((parts.scheme, parts.netloc, parts.path or "/", parts.query, ""))


def candidates(
    page_url: str, links: list[str], assets: list[dict[str, str]], target_url: str
) -> list[tuple[str, str]]:
    """``(kind, url)`` to request: same-origin, de-duplicated, fragments dropped, capped."""
    seen = {_normalise(page_url)}
    out: list[tuple[str, str]] = []
    wanted = [("link", u) for u in links] + [(a["tag"], a["url"]) for a in assets]
    for kind, raw in wanted:
        url = _normalise(raw)
        if url in seen or not same_origin(url, target_url):
            continue
        seen.add(url)
        out.append((kind, url))
        if len(out) >= MAX_REQUESTS:
            break
    return out


def is_broken(status: int) -> bool:
    return status in (404, 410) or status >= 500


async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
    """Report same-origin links and assets that answer 404/410 or 5xx."""
    page_url = target_path_url(ctx)
    if await safe_navigate(page, ctx, page_url) is None:
        return []
    shots = await screenshot_or_none(ctx, "links_assets")
    evidence = [*shots, NETWORK_SUMMARY]
    todo = candidates(page_url, await page_links(page), await page_assets(page), ctx.target_url)

    found: list[dict[str, Any]] = []
    for kind, url in todo:
        got = await fetch(page, ctx, url)
        if got is None or not is_broken(got.status):
            continue
        path = path_of(url)
        origin = path_of(page_url)
        if kind == "link":
            title = f"Broken link: {path} returns HTTP {got.status}"
            steps = [f"Open {origin}", f"Click the link to {path}"]
            severity = "high" if got.status >= 500 else "medium"
            impact = "Visitors who follow this link land on an error page."
            fix = "Fix or remove the link, or restore the page it points to."
        else:
            label = _ASSET_LABEL[kind]
            title = f"Broken {label}: {path} returns HTTP {got.status}"
            steps = [f"Open {origin}", f"Observe the {label} {path} fails to load"]
            severity = _ASSET_SEVERITY[kind]
            impact = (
                "The page renders without its images."
                if kind == "img"
                else f"The page may be unstyled or lose features without this {label}."
            )
            fix = f"Fix the {label} URL or deploy the missing file."
        found.append(
            qa_finding(
                check_id=CHECK_ID,
                title=title,
                severity=severity,
                url=url,
                evidence=evidence,
                reproduction=[*steps, f"Observe HTTP {got.status}"],
                impact=impact,
                recommended_fix=fix,
                confidence=0.95,
            )
        )
        if len(found) >= MAX_FINDINGS:
            break
    return found
