"""qa.login: does the login page work and handle bad credentials sanely? (brief 3, 6.5)

Opens the login page (``params.path``, default ``/login``) and submits the login form at most
twice: once with a marked non-existent account (``agentguard-probe-<id>@example.invalid``) and
a marked wrong password, once with empty fields. No real accounts, no password lists, redirects
not followed. Credentials never come from the LLM or the plan.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from checks.context import CheckContext
from checks.qa._common import (
    build_payload,
    default_path_url,
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
)

CHECK_ID = "qa.login"

_ACCOUNT_AREA = re.compile(
    r"(?i)/(?:account|dashboard|profile|welcome|home|admin|my[-_]?account)\b"
)
_LOGIN_LIKE = re.compile(r"(?i)login|log-in|signin|sign-in|error|fail|invalid|denied|retry")


def login_form(forms: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The first POST form with exactly one password field."""
    for form in forms:
        passwords = [i for i in named_inputs(form) if i.get("type") == "password"]
        if is_post_form(form) and len(passwords) == 1:
            return form
    return None


def logged_in_redirect(status: int, location: str) -> bool:
    """True if a 3xx sends the visitor into an account area, not back to the login page."""
    if not 300 <= status < 400 or not location:
        return False
    path = urlsplit(location).path + "?" + urlsplit(location).query
    return bool(_ACCOUNT_AREA.search(path)) and not _LOGIN_LIKE.search(path)


async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
    """Open the login page, submit a fake account and an empty form."""
    login_url, explicit = default_path_url(ctx, "/login")
    path = path_of(login_url)
    response = await safe_navigate(page, ctx, login_url)
    if response is None:
        return []
    shots = await screenshot_or_none(ctx, "login")
    evidence = [*shots, NETWORK_SUMMARY]

    if response.status >= 500 or (response.status == 404 and explicit):
        return [
            qa_finding(
                check_id=CHECK_ID,
                title=f"Login page {path} returns HTTP {response.status}",
                severity="high",
                url=login_url,
                evidence=evidence,
                reproduction=[f"Open {path}", f"Observe HTTP {response.status} instead of a form"],
                impact="Customers cannot sign in.",
                recommended_fix="Fix the login route and add an uptime check on it.",
            )
        ]
    if response.status >= 400:
        return []  # no login page here (or it needs auth): nothing to test

    form = login_form(await page_forms(page))
    if form is None:
        ctx.record_request({"url": login_url, "skipped": "no login form found"})
        return []
    action = str(form.get("action") or "")
    if not same_origin(action, ctx.target_url):
        ctx.record_request({"url": login_url, "skipped": "login form posts off-origin"})
        return []

    marker = probe_marker(ctx)
    payload = build_payload(form, marker)
    bad = await fetch(page, ctx, action, form=payload)
    if bad is None:
        return []
    found: list[dict[str, Any]] = []
    if bad.status >= 500:
        found.append(
            qa_finding(
                check_id=CHECK_ID,
                title=f"Login crashes on invalid credentials (HTTP {bad.status})",
                severity="high",
                url=action,
                evidence=evidence,
                reproduction=[
                    f"Open {path}",
                    "Submit the form with an unknown email and a wrong password",
                    f"Observe HTTP {bad.status} instead of an 'invalid credentials' message",
                ],
                impact="Mistyped credentials produce an error page, and failures may lock real "
                "users out or hide an auth bug.",
                recommended_fix="Handle unknown accounts and wrong passwords explicitly and "
                "answer 401/200 with a generic 'invalid email or password' message.",
            )
        )
    elif logged_in_redirect(bad.status, bad.location):
        found.append(
            qa_finding(
                check_id=CHECK_ID,
                title="Login appears to accept a non-existent account",
                severity="critical",
                url=action,
                evidence=evidence,
                reproduction=[
                    f"Open {path}",
                    "Submit the form with an unknown, marked email and a wrong password",
                    f"Observe HTTP {bad.status} redirecting to {path_of(bad.location)}",
                ],
                impact="If real, anyone can sign in without an account: broken authentication.",
                recommended_fix="Verify credentials server-side before creating a session and "
                "reject unknown accounts.",
                confidence=0.45,  # heuristic on a redirect: the Verifier must confirm it
            )
        )

    empty = await fetch(page, ctx, action, form=build_payload(form, marker, blank=True))
    if empty is not None and empty.status >= 500 and bad.status < 500:
        found.append(
            qa_finding(
                check_id=CHECK_ID,
                title=f"Login crashes on empty fields (HTTP {empty.status})",
                severity="medium",
                url=action,
                evidence=evidence,
                reproduction=[
                    f"Open {path}",
                    "Submit the login form with both fields empty",
                    f"Observe HTTP {empty.status} instead of a validation message",
                ],
                impact="Empty submissions crash the handler instead of showing guidance.",
                recommended_fix="Validate required fields before authenticating.",
                confidence=0.85,
            )
        )
    return found
