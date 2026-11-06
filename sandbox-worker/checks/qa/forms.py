"""qa.forms: do forms handle valid and invalid input without crashing? (brief 3, 6.5)

Finds up to 3 same-origin POST forms on the page (login, password and card forms are left to
their own checks), submits each once with harmless marked values and, if that works, once with
every field empty. Redirects are not followed. Reports server errors and dead form actions.
"""

from __future__ import annotations

from typing import Any

from checks.context import CheckContext
from checks.qa._common import (
    MAX_FORMS,
    build_payload,
    has_password,
    is_post_form,
    named_inputs,
    qa_finding,
    safe_navigate,
)
from checks.security._common import (
    NETWORK_SUMMARY,
    fetch,
    page_forms,
    path_of,
    probe_marker,
    same_origin,
    screenshot_or_none,
    target_path_url,
)

CHECK_ID = "qa.forms"


def candidate_forms(forms: list[dict[str, Any]], target_url: str) -> list[dict[str, Any]]:
    """POST forms with fields, on the target origin, without a password field."""
    out = [
        f
        for f in forms
        if is_post_form(f)
        and not has_password(f)
        and named_inputs(f)
        and same_origin(str(f.get("action") or ""), target_url)
    ]
    return out[:MAX_FORMS]


def form_label(form: dict[str, Any]) -> str:
    """Short description for titles: the action path."""
    return path_of(str(form.get("action") or "/"))


async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
    """Submit each candidate form with valid and then invalid data."""
    page_url = target_path_url(ctx)
    if await safe_navigate(page, ctx, page_url) is None:
        return []
    forms = candidate_forms(await page_forms(page), ctx.target_url)
    if not forms:
        ctx.record_request({"url": page_url, "skipped": "no testable POST form found"})
        return []
    shots = await screenshot_or_none(ctx, "forms")
    evidence = [*shots, NETWORK_SUMMARY]
    marker = probe_marker(ctx)
    origin = path_of(page_url)

    found: list[dict[str, Any]] = []
    for form in forms:
        action = str(form["action"])
        label = form_label(form)
        valid = await fetch(page, ctx, action, form=build_payload(form, marker))
        if valid is None:
            continue
        if valid.status >= 500 or valid.status in (404, 405):
            kind = "fails" if valid.status >= 500 else "points nowhere"
            found.append(
                qa_finding(
                    check_id=CHECK_ID,
                    title=f"Form posting to {label} {kind} (HTTP {valid.status})",
                    severity="high",
                    url=action,
                    evidence=evidence,
                    reproduction=[
                        f"Open {origin}",
                        "Fill the form with ordinary values and submit it",
                        f"Observe HTTP {valid.status} instead of a confirmation",
                    ],
                    impact="Visitors cannot send the form, so messages, orders or sign-ups "
                    "are lost.",
                    recommended_fix="Check the server log for this endpoint, fix the handler "
                    "and return a clear confirmation or validation message.",
                )
            )
            continue
        invalid = await fetch(page, ctx, action, form=build_payload(form, marker, blank=True))
        if invalid is not None and invalid.status >= 500:
            found.append(
                qa_finding(
                    check_id=CHECK_ID,
                    title=f"Form posting to {label} crashes on empty input (HTTP {invalid.status})",
                    severity="medium",
                    url=action,
                    evidence=evidence,
                    reproduction=[
                        f"Open {origin}",
                        "Submit the form with every field empty",
                        f"Observe HTTP {invalid.status} instead of a validation message",
                    ],
                    impact="Unvalidated input can crash the handler and shows visitors an error "
                    "page instead of guidance.",
                    recommended_fix="Validate required fields on the server and answer 400/422 "
                    "with a clear message.",
                    confidence=0.85,
                )
            )
    return found
