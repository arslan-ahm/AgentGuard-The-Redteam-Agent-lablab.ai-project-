"""qa.password_reset: does "forgot password" work? (brief 3, 6.5)

Finds the reset page (``params.path``, else the first of ``/password-reset``,
``/forgot-password``, ``/reset-password``, ``/forgot`` that holds an email form), then submits
it with a marked non-existent address (``agentguard-probe-<id>@example.invalid``) and with a
malformed one. No real address is ever used, so no real user gets an email. Redirects are not
followed. A site with no reset page is not a failure: the check just reports nothing.
"""

from __future__ import annotations

from typing import Any

from checks.context import CheckContext
from checks.qa._common import (
    build_payload,
    default_path_url,
    email_field_names,
    has_password,
    is_post_form,
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
)

CHECK_ID = "qa.password_reset"

DEFAULT_PATHS = ("/password-reset", "/forgot-password", "/reset-password", "/forgot")


def reset_form(forms: list[dict[str, Any]], target_url: str) -> dict[str, Any] | None:
    """First same-origin POST form with an email field and no password field."""
    for form in forms:
        if (
            is_post_form(form)
            and not has_password(form)
            and email_field_names(form)
            and same_origin(str(form.get("action") or ""), target_url)
        ):
            return form
    return None


async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
    """Locate the reset form, submit a fake and a malformed address."""
    first, explicit = default_path_url(ctx, DEFAULT_PATHS[0])
    urls = [first] if explicit else [default_path_url(ctx, p)[0] for p in DEFAULT_PATHS]

    form: dict[str, Any] | None = None
    page_url = first
    evidence: list[str] = [NETWORK_SUMMARY]
    for url in urls:
        response = await safe_navigate(page, ctx, url)
        if response is None:
            continue
        path = path_of(url)
        if response.status >= 500 or (response.status == 404 and explicit):
            shots = await screenshot_or_none(ctx, "password_reset")
            return [
                qa_finding(
                    check_id=CHECK_ID,
                    title=f"Password reset page {path} returns HTTP {response.status}",
                    severity="high" if response.status >= 500 else "medium",
                    url=url,
                    evidence=[*shots, NETWORK_SUMMARY],
                    reproduction=[
                        f"Open {path}",
                        f"Observe HTTP {response.status} instead of a reset form",
                    ],
                    impact="Customers who forgot their password cannot recover their account.",
                    recommended_fix="Fix the reset route and add an uptime check on it.",
                )
            ]
        if response.status >= 400:
            continue
        form = reset_form(await page_forms(page), ctx.target_url)
        if form is not None:
            page_url = url
            evidence = [*await screenshot_or_none(ctx, "password_reset"), NETWORK_SUMMARY]
            break
        if explicit:
            shots = await screenshot_or_none(ctx, "password_reset")
            return [
                qa_finding(
                    check_id=CHECK_ID,
                    title=f"Password reset page {path} has no email form",
                    severity="medium",
                    url=url,
                    evidence=[*shots, NETWORK_SUMMARY],
                    reproduction=[f"Open {path}", "Look for a form asking for an email address"],
                    impact="Customers cannot request a password reset from this page.",
                    recommended_fix="Add a form with an email field that posts to the reset "
                    "endpoint.",
                    confidence=0.75,
                )
            ]
    if form is None:
        ctx.record_request({"url": first, "skipped": "no password reset page found"})
        return []

    action = str(form["action"])
    path = path_of(page_url)
    marker = probe_marker(ctx)
    found: list[dict[str, Any]] = []

    good = await fetch(page, ctx, action, form=build_payload(form, marker))
    if good is not None and good.status >= 500:
        found.append(
            qa_finding(
                check_id=CHECK_ID,
                title=f"Password reset fails for an unknown address (HTTP {good.status})",
                severity="high",
                url=action,
                evidence=evidence,
                reproduction=[
                    f"Open {path}",
                    "Submit the form with an email address that has no account",
                    f"Observe HTTP {good.status} instead of a neutral confirmation",
                ],
                impact="Password recovery breaks, and the error can reveal which addresses "
                "have accounts.",
                recommended_fix="Always answer with the same confirmation message, whether or "
                "not the account exists, and handle the missing-account case in code.",
            )
        )
        return found

    payload = build_payload(form, marker)
    for name in email_field_names(form):
        payload[name] = "not-an-email"
    bad = await fetch(page, ctx, action, form=payload)
    if bad is not None and bad.status >= 500:
        found.append(
            qa_finding(
                check_id=CHECK_ID,
                title=f"Password reset crashes on a malformed address (HTTP {bad.status})",
                severity="medium",
                url=action,
                evidence=evidence,
                reproduction=[
                    f"Open {path}",
                    "Submit the form with the text 'not-an-email'",
                    f"Observe HTTP {bad.status} instead of a validation message",
                ],
                impact="Bad input crashes the handler instead of guiding the visitor.",
                recommended_fix="Validate the email address and answer 400/422 with a message.",
                confidence=0.85,
            )
        )
    return found
