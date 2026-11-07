"""Test doubles for the QA checks: a fake Playwright page, nothing touches the network."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from agentguard_contracts import FindingDraft
from playwright.async_api import Error as PlaywrightError

from checks.context import CheckContext, SameOriginPolicy

TARGET = "https://shop.example.com"
HTML_OK = "<html><head><title>Shop</title></head><body>ok</body></html>"


class FakeResponse:
    """A navigation response (``page.goto``)."""

    def __init__(self, status: int = 200, body: str = HTML_OK) -> None:
        self.status = status
        self.url = ""
        self._body = body

    async def all_headers(self) -> dict[str, str]:
        return {"content-type": "text/html"}

    async def text(self) -> str:
        return self._body


class FakeAPIResponse:
    """A ``page.request`` response."""

    def __init__(
        self, status: int = 200, hdrs: dict[str, str] | None = None, body: str = ""
    ) -> None:
        self.status = status
        self.headers = {k.lower(): v for k, v in (hdrs or {}).items()}
        self._body = body

    async def text(self) -> str:
        return self._body


PostHandler = Callable[[dict[str, str]], FakeAPIResponse]


class FakeRequestAPI:
    """``page.request``: records every call so tests can assert what was (not) sent."""

    def __init__(self) -> None:
        self.gets: dict[str, FakeAPIResponse | Exception] = {}
        self.posts: dict[str, FakeAPIResponse | PostHandler] = {}
        self.get_calls: list[str] = []
        self.post_calls: list[tuple[str, dict[str, str]]] = []
        self.default_status = 200

    async def get(
        self, url: str, max_redirects: int, timeout: int  # noqa: ASYNC109 - Playwright API
    ) -> FakeAPIResponse:
        assert max_redirects == 0 and timeout > 0
        self.get_calls.append(url)
        route = self.gets.get(url, FakeAPIResponse(self.default_status))
        if isinstance(route, Exception):
            raise route
        return route

    async def post(
        self,
        url: str,
        form: dict[str, str],
        max_redirects: int,
        timeout: int,  # noqa: ASYNC109 - Playwright API
    ) -> FakeAPIResponse:
        assert max_redirects == 0 and timeout > 0
        self.post_calls.append((url, dict(form)))
        route = self.posts.get(url, FakeAPIResponse(200))
        return route(form) if callable(route) else route


@dataclass
class FakePage:
    """Just enough of ``playwright.async_api.Page`` for the QA checks."""

    routes: dict[str, FakeResponse | Exception] = field(default_factory=dict)
    dom: dict[str, list[Any]] = field(default_factory=dict)
    forms: list[dict[str, Any]] = field(default_factory=list)
    scan: Any = None
    emit_on_goto: list[tuple[str, Any]] = field(default_factory=list)
    never_idle: bool = False
    request: FakeRequestAPI = field(default_factory=FakeRequestAPI)
    visited: list[str] = field(default_factory=list)
    _handlers: dict[str, list[Callable[[Any], None]]] = field(default_factory=dict)

    def on(self, event: str, handler: Callable[[Any], None]) -> None:
        self._handlers.setdefault(event, []).append(handler)

    def remove_listener(self, event: str, handler: Callable[[Any], None]) -> None:
        self._handlers[event].remove(handler)

    def listeners(self) -> int:
        return sum(len(v) for v in self._handlers.values())

    async def goto(
        self, url: str, timeout: int, wait_until: str  # noqa: ASYNC109 - Playwright API
    ) -> FakeResponse:
        assert timeout > 0
        self.visited.append(url)
        route = self.routes.get(url, FakeResponse())
        if isinstance(route, Exception):
            raise route
        route.url = url
        for event, payload in self.emit_on_goto:
            for handler in list(self._handlers.get(event, [])):
                handler(payload)
        return route

    async def wait_for_load_state(
        self, state: str, timeout: int  # noqa: ASYNC109 - Playwright API
    ) -> None:
        if self.never_idle:
            raise PlaywrightError("Timeout 3000ms exceeded")

    async def eval_on_selector_all(self, selector: str, expression: str) -> list[Any]:
        if selector == "form":
            return self.forms
        return self.dom.get(selector, [])

    async def evaluate(self, expression: str) -> Any:
        if isinstance(self.scan, Exception):
            raise self.scan
        return self.scan

    async def screenshot(self, path: str, full_page: bool) -> None:
        await asyncio.to_thread(Path(path).write_bytes, b"png")


@dataclass
class Console:
    type: str
    text: str


@dataclass
class PageError:
    message: str


@dataclass
class FailedRequest:
    url: str
    failure: str | None = "net::ERR_CONNECTION_REFUSED"


@dataclass
class SeenResponse:
    url: str
    status: int


def make_ctx(tmp_path: Path, page: FakePage, target: str = TARGET, **params: Any) -> CheckContext:
    return CheckContext(
        target_url=target,
        params=dict(params),
        evidence_dir=tmp_path,
        policy=SameOriginPolicy(target),
        page=page,
    )


def form(
    action: str,
    fields: list[tuple[str, str]],
    method: str = "post",
    values: dict[str, str] | None = None,
) -> dict[str, Any]:
    """A form dict in the shape ``page_forms`` returns."""
    values = values or {}
    return {
        "action": action,
        "method": method,
        "inputs": [{"name": n, "type": t, "value": values.get(n, "")} for n, t in fields],
    }


def titles(found: list[dict[str, Any]]) -> list[str]:
    return [f["title"] for f in found]


def assert_contract(found: list[dict[str, Any]], check_id: str, category: str = "qa") -> None:
    """Every finding validates against brief 5.4 and carries evidence and repro steps."""
    for item in found:
        draft = FindingDraft.model_validate(item)
        assert draft.check_id == check_id
        assert draft.category.value == category
        assert draft.reproduction and draft.evidence and draft.recommended_fix
        assert "network_summary.json" in draft.evidence
