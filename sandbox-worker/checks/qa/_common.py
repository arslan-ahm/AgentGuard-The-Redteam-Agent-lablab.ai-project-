"""Shared helpers for QA checks. Not a check module (no CHECK_ID), never loaded by id.

Navigation and requests go through ``checks.security._common`` (policy check first, redirects
never followed, safe headers only), so every QA check obeys the same containment rules.
Probe values are always harmless and clearly marked: an ``agentguard-probe-<id>`` marker, an
``@example.invalid`` address, and **never** a real card number (payment fields get zeros).
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin

from playwright.async_api import Error as PlaywrightError

from checks.context import CheckContext
from checks.security._common import MAX_BODY_CHARS, finding, navigate

MAX_FORMS = 3
_SKIP_TYPES = frozenset({"submit", "button", "image", "reset", "file"})

_CVC = re.compile(r"(?i)cvv|cvc|csc|security[-_ ]?code")
_CARD = re.compile(r"(?i)card[-_ ]?(?:num|no)|cc[-_ ]?num|cardnumber|^card$|payment[-_ ]?number")
_EXPIRY = re.compile(r"(?i)exp")
_EMAIL = re.compile(r"(?i)e-?mail")
_ZIP = re.compile(r"(?i)zip|postal|post_?code")
_PHONE = re.compile(r"(?i)phone|tel|mobile")
_NAME = re.compile(r"(?i)name")
_REDACT = re.compile(
    r"(?i)(token|secret|password|passwd|apikey|api_key|authorization|bearer|session)"
    r"([=:\s\"']+)(?:(?:bearer|basic)\s+)?[^\s\"',;&]{3,}"
)


def qa_finding(
    *,
    check_id: str,
    title: str,
    severity: str,
    url: str,
    evidence: list[str],
    reproduction: list[str],
    impact: str,
    recommended_fix: str,
    confidence: float = 0.9,
    category: str = "qa",
) -> dict[str, Any]:
    """A Finding dict (brief 5.4 without id/scan_id) in the ``qa`` or ``accessibility`` category."""
    item = finding(
        check_id=check_id,
        title=title,
        severity=severity,
        url=url,
        evidence=evidence,
        reproduction=reproduction,
        impact=impact,
        recommended_fix=recommended_fix,
        confidence=confidence,
    )
    item["category"] = category
    return item


def first_line(exc: BaseException) -> str:
    """One short line describing an exception, for ``network_summary.json``."""
    text = str(exc).splitlines()[0][:200] if str(exc) else ""
    return text or type(exc).__name__


async def safe_navigate(page: Any, ctx: CheckContext, url: str) -> Any | None:
    """``navigate`` that turns a browser error (timeout, DNS, refused) into ``None``.

    A ``PolicyViolation`` is deliberately **not** caught: it must end the task as blocked.
    """
    try:
        return await navigate(page, ctx, url)
    except PlaywrightError as exc:
        ctx.record_request({"url": url, "status": None, "error": first_line(exc)})
        return None


async def response_body(response: Any) -> str:
    """Response text, truncated; empty if the body is binary or unreadable."""
    try:
        return str(await response.text())[:MAX_BODY_CHARS]
    except Exception:  # binary or aborted body: nothing to analyse
        return ""


def default_path_url(ctx: CheckContext, default: str) -> tuple[str, bool]:
    """``(url, explicit)``: ``params.path`` on the target origin if given, else ``default``."""
    path = ctx.params.get("path")
    if isinstance(path, str) and path.startswith("/") and not path.startswith("//"):
        return urljoin(ctx.target_url, path), True
    return urljoin(ctx.target_url, default), False


def redact(text: str, limit: int = 300) -> str:
    """Truncate, collapse whitespace and mask anything that looks like a secret."""
    flat = " ".join(text.split())[:limit]
    return _REDACT.sub(lambda m: f"{m.group(1)}{m.group(2)}[redacted]", flat)


def is_post_form(form: dict[str, Any]) -> bool:
    return form.get("method") == "post"


def has_password(form: dict[str, Any]) -> bool:
    return any(
        isinstance(i, dict) and i.get("type") == "password" for i in form.get("inputs") or []
    )


def named_inputs(form: dict[str, Any]) -> list[dict[str, Any]]:
    return [i for i in form.get("inputs") or [] if isinstance(i, dict) and i.get("name")]


def email_field_names(form: dict[str, Any]) -> list[str]:
    """Names of inputs that take an email address (type=email or an email-like name)."""
    return [
        str(i["name"])
        for i in named_inputs(form)
        if i.get("type") == "email" or _EMAIL.search(str(i["name"]))
    ]


def _value_for(name: str, kind: str, marker: str) -> str:
    if kind == "email" or _EMAIL.search(name):
        return f"{marker}@example.invalid"
    if kind == "number":
        return "1"
    if kind == "url":
        return "https://example.invalid"
    if kind == "date":
        return "2030-01-01"
    if kind == "password":
        return f"{marker}-pw"
    if _CVC.search(name):
        return "000"
    if _CARD.search(name):
        return "0000000000000000"  # never a real or well-known test card number
    if _EXPIRY.search(name):
        return "12/34"
    if kind == "tel" or _PHONE.search(name):
        return "0000000000"
    if _ZIP.search(name):
        return "00000"
    if _NAME.search(name):
        return "AgentGuard Probe"
    return marker


def build_payload(form: dict[str, Any], marker: str, *, blank: bool = False) -> dict[str, str]:
    """Field values for one submission.

    Hidden fields are kept as-is (CSRF tokens). ``blank`` sends every visible field empty to
    test input validation; otherwise each field gets a harmless, marked probe value.
    """
    payload: dict[str, str] = {}
    radios: set[str] = set()
    for item in named_inputs(form):
        name, kind = str(item["name"]), str(item.get("type", "text"))
        if kind in _SKIP_TYPES:
            continue
        if kind == "hidden":
            payload[name] = str(item.get("value", ""))[:4096]
        elif kind == "radio":
            if name not in radios and not blank:
                radios.add(name)
                payload[name] = str(item.get("value") or "on")[:200]
        elif kind == "checkbox":
            if not blank:
                payload[name] = str(item.get("value") or "on")[:200]
        elif blank:
            payload[name] = ""
        else:
            payload[name] = _value_for(name, kind, marker)
    return payload
