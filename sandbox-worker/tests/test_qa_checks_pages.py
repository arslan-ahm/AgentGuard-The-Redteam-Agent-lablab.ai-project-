"""QA checks that read pages: pages_load, links_assets, console_network_errors, accessibility.

Each check has a flawed and a clean case against a fake page (``tests/qa_fakes.py``).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from playwright.async_api import Error as PlaywrightError

from checks.context import PolicyViolation
from checks.qa import accessibility, console_network_errors, links_assets, pages_load
from tests.qa_fakes import (
    TARGET,
    Console,
    FailedRequest,
    FakeAPIResponse,
    FakePage,
    FakeResponse,
    PageError,
    SeenResponse,
    assert_contract,
    make_ctx,
    titles,
)

# --- pages_load ----------------------------------------------------------------------


async def test_pages_load_clean(tmp_path: Path) -> None:
    page = FakePage()
    found = await pages_load.run(page, make_ctx(tmp_path, page))
    assert found == []
    assert page.visited == [TARGET]


async def test_pages_load_reports_5xx_404_and_missing_title(tmp_path: Path) -> None:
    page = FakePage(
        routes={
            f"{TARGET}/boom": FakeResponse(500),
            f"{TARGET}/gone": FakeResponse(404),
            f"{TARGET}/untitled": FakeResponse(200, "<html><body>hi</body></html>"),
        }
    )
    ctx = make_ctx(tmp_path, page, paths=["/boom", "/gone", "/untitled", "/ok"])
    found = await pages_load.run(page, ctx)
    assert titles(found) == [
        "Page /boom returns HTTP 500",
        "Page /gone returns HTTP 404",
        "Page /untitled has no title",
    ]
    assert [f["severity"] for f in found] == ["high", "medium", "low"]
    assert_contract(found, "qa.pages_load")


async def test_pages_load_failure_to_load_is_reported(tmp_path: Path) -> None:
    page = FakePage(routes={f"{TARGET}/": PlaywrightError("net::ERR_CONNECTION_TIMED_OUT")})
    found = await pages_load.run(page, make_ctx(tmp_path, page, path="/"))
    assert titles(found) == ["Page / failed to load"]
    assert found[0]["severity"] == "high"
    assert_contract(found, "qa.pages_load")


async def test_pages_load_slow_page(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ticks = iter([0.0, pages_load.SLOW_MS / 1000 + 2])
    monkeypatch.setattr(pages_load, "_clock", lambda: next(ticks))
    page = FakePage()
    found = await pages_load.run(page, make_ctx(tmp_path, page))
    assert len(found) == 1 and found[0]["title"].startswith("Page / loads slowly")
    assert_contract(found, "qa.pages_load")


async def test_pages_load_ignores_bad_paths_and_caps_pages(tmp_path: Path) -> None:
    page = FakePage()
    paths = ["//evil.example.com/x", "http://evil.example.com", *[f"/p{i}" for i in range(9)]]
    await pages_load.run(page, make_ctx(tmp_path, page, paths=paths))
    assert page.visited == [f"{TARGET}/p{i}" for i in range(pages_load.MAX_PAGES)]


async def test_pages_load_off_origin_navigation_is_a_policy_violation(tmp_path: Path) -> None:
    """The check never builds an off-origin URL, but the policy would stop it if it did."""
    page = FakePage()
    ctx = make_ctx(tmp_path, page)
    with pytest.raises(PolicyViolation):
        ctx.policy.assert_allowed("https://evil.example.com/")


# --- links_assets --------------------------------------------------------------------

LINKS = "a[href]"
ASSETS = "img[src], script[src], link[rel~='stylesheet'][href]"


async def test_links_assets_reports_broken_link_and_missing_image(tmp_path: Path) -> None:
    page = FakePage(
        dom={
            LINKS: [f"{TARGET}/products", f"{TARGET}/old-sale", "https://evil.example.com/x"],
            ASSETS: [
                {"tag": "img", "url": f"{TARGET}/img/logo.png"},
                {"tag": "script", "url": f"{TARGET}/app.js"},
            ],
        }
    )
    page.request.gets[f"{TARGET}/old-sale"] = FakeAPIResponse(404)
    page.request.gets[f"{TARGET}/img/logo.png"] = FakeAPIResponse(404)
    found = await links_assets.run(page, make_ctx(tmp_path, page))
    assert titles(found) == [
        "Broken link: /old-sale returns HTTP 404",
        "Broken image: /img/logo.png returns HTTP 404",
    ]
    assert [f["severity"] for f in found] == ["medium", "low"]
    assert_contract(found, "qa.links_assets")
    # off-origin links are never requested
    assert all(u.startswith(TARGET) for u in page.request.get_calls)


async def test_links_assets_5xx_link_is_high(tmp_path: Path) -> None:
    page = FakePage(dom={LINKS: [f"{TARGET}/crash"]})
    page.request.gets[f"{TARGET}/crash"] = FakeAPIResponse(500)
    found = await links_assets.run(page, make_ctx(tmp_path, page))
    assert found[0]["severity"] == "high"


async def test_links_assets_clean_and_deduplicated(tmp_path: Path) -> None:
    page = FakePage(
        dom={
            LINKS: [f"{TARGET}/a", f"{TARGET}/a#top", f"{TARGET}/", "mailto:x@example.invalid"],
            ASSETS: [{"tag": "link", "url": f"{TARGET}/site.css"}],
        }
    )
    found = await links_assets.run(page, make_ctx(tmp_path, page))
    assert found == []
    assert page.request.get_calls == [f"{TARGET}/a", f"{TARGET}/site.css"]


async def test_links_assets_caps_requests(tmp_path: Path) -> None:
    page = FakePage(dom={LINKS: [f"{TARGET}/l{i}" for i in range(200)]})
    await links_assets.run(page, make_ctx(tmp_path, page))
    assert len(page.request.get_calls) == links_assets.MAX_REQUESTS


# --- console_network_errors ----------------------------------------------------------


async def test_console_errors_page_errors_and_failed_requests(tmp_path: Path) -> None:
    page = FakePage(
        emit_on_goto=[
            ("console", Console("error", "Failed to load product list")),
            ("console", Console("log", "hello")),
            ("console", Console("warning", "deprecated API")),
            ("pageerror", PageError("TypeError: x is undefined")),
            ("response", SeenResponse(f"{TARGET}/api/cart?token=abc123", 500)),
            ("response", SeenResponse(f"{TARGET}/favicon.ico", 404)),
            ("response", SeenResponse("https://cdn.example.net/x.js", 404)),
            ("response", SeenResponse(f"{TARGET}/ok.js", 200)),
            ("requestfailed", FailedRequest(f"{TARGET}/img/hero.png")),
        ]
    )
    found = await console_network_errors.run(page, make_ctx(tmp_path, page))
    assert titles(found) == [
        "Uncaught JavaScript error on /",
        "Console errors on / (1)",
        "2 failing request(s) on /",
        "Console warnings on / (1)",
    ]
    assert [f["severity"] for f in found] == ["medium", "medium", "medium", "low"]
    assert_contract(found, "qa.console_network_errors")
    assert page.listeners() == 0  # handlers are always removed
    summary = " ".join(f["reproduction"][1] for f in found)
    assert "abc123" not in summary and "?token" not in summary  # query strings never leak
    assert "cdn.example.net" not in summary and "favicon" not in summary


async def test_console_redacts_secrets(tmp_path: Path) -> None:
    page = FakePage(emit_on_goto=[("console", Console("error", "auth failed token=s3cr3tvalue99"))])
    ctx = make_ctx(tmp_path, page)
    found = await console_network_errors.run(page, ctx)
    assert "s3cr3tvalue99" not in found[0]["reproduction"][1]
    assert all("s3cr3tvalue99" not in str(r) for r in ctx.requests)


async def test_console_clean_page_and_never_idle_page(tmp_path: Path) -> None:
    page = FakePage(emit_on_goto=[("console", Console("log", "fine"))], never_idle=True)
    assert await console_network_errors.run(page, make_ctx(tmp_path, page)) == []
    assert page.listeners() == 0


async def test_console_unreachable_page_removes_handlers(tmp_path: Path) -> None:
    page = FakePage(routes={f"{TARGET}/": PlaywrightError("net::ERR_FAILED")})
    assert await console_network_errors.run(page, make_ctx(tmp_path, page)) == []
    assert page.listeners() == 0


# --- accessibility -------------------------------------------------------------------

CLEAN_SCAN = {
    "images": [],
    "inputs": [],
    "links": [],
    "buttons": [],
    "contrast": [],
    "lang": "en",
    "title": "Shop",
}


async def test_accessibility_clean(tmp_path: Path) -> None:
    page = FakePage(scan=dict(CLEAN_SCAN))
    assert await accessibility.run(page, make_ctx(tmp_path, page)) == []


async def test_accessibility_reports_each_problem(tmp_path: Path) -> None:
    scan = {
        "images": ["/img/banner.png", "/img/logo.png"],
        "inputs": ["email"],
        "links": ["/cart"],
        "buttons": ["go"],
        "contrast": [{"text": "Sale ends soon", "ratio": 1.4}],
        "lang": "",
        "title": "",
    }
    page = FakePage(scan=scan)
    found = await accessibility.run(page, make_ctx(tmp_path, page))
    assert titles(found) == [
        "2 image(s) without alt text",
        "1 form field(s) without a label",
        "1 link(s) with no text",
        "1 button(s) with no accessible name",
        "Page has no title",
        "Page language is not declared",
        "Low text contrast on 1 element(s)",
    ]
    assert found[0]["severity"] == "low" and found[1]["severity"] == "medium"
    assert_contract(found, "qa.accessibility", category="accessibility")


async def test_accessibility_survives_blocked_scan_and_junk(tmp_path: Path) -> None:
    blocked = FakePage(scan=PlaywrightError("CSP blocked evaluate"))
    assert await accessibility.run(blocked, make_ctx(tmp_path, blocked)) == []
    junk = FakePage(scan="not a dict")
    assert await accessibility.run(junk, make_ctx(tmp_path, junk)) == []


def test_accessibility_scan_js_is_wellformed() -> None:
    js = accessibility.SCAN_JS
    assert "%MIN%" not in js and js.count("{") == js.count("}") and "rgba?\\(" in js
