"""security.login_rate_probe: are failed logins limited at all? (brief 3, 6.6)

At most **3** login attempts, hard-coded (``params.attempts`` can lower it, never raise it).
Each attempt reloads the login page (fresh CSRF token) and posts the form once with a marked,
non-existent account (``agentguard-probe-<id>@example.invalid``) and a marked wrong
password, redirects not followed. No password lists, no real accounts, nothing changes.

Three attempts can't prove a limit is missing, only that none showed up early, so the
finding is ``medium`` with ``confidence`` 0.6 for the Verifier to weigh.
"""

from __future__ import annotations

import re
from typing import Any

from checks.context import CheckContext
from checks.security._common import (
    NETWORK_SUMMARY,
    Fetched,
    fetch,
    finding,
    navigate,
    page_forms,
    path_of,
    probe_marker,
    same_origin,
    target_path_url,
)

CHECK_ID = "security.login_rate_probe"

MAX_ATTEMPTS = 3
_USER_HINT = re.compile(r"(?i)user|email|login|account|ident")
_SKIP_TYPES = frozenset(
    {"password", "hidden", "checkbox", "radio", "submit", "button", "image", "file", "reset"}
)
_LIMITED = re.compile(
    r"too many (?:failed |login |sign[- ]in )?(?:attempts|requests|tries)|rate[- ]limit|"
    r"temporarily (?:locked|blocked|disabled)|account (?:is |has been )?locked|"
    r"try again (?:later|in \d)|captcha|cf-turnstile|h-captcha|g-recaptcha",
    re.IGNORECASE,
)


def login_form(forms: list[dict[str, Any]]) -> dict[str, Any] | None:
    """The first POST form with exactly one password field (login, not sign-up/change)."""
    for form in forms:
        inputs = [i for i in form.get("inputs") or [] if isinstance(i, dict)]
        passwords = [i for i in inputs if i.get("type") == "password"]
        if form.get("method") == "post" and len(passwords) == 1:
            return form
    return None


def form_payload(form: dict[str, Any], user: str, password: str) -> dict[str, str] | None:
    """Field values for one attempt: hidden fields kept (CSRF), probe user and password set.
    None if no username field can be identified."""
    inputs = [i for i in form.get("inputs") or [] if isinstance(i, dict) and i.get("name")]
    texts = [i for i in inputs if str(i.get("type", "")) not in _SKIP_TYPES]
    hinted = [i for i in texts if _USER_HINT.search(str(i["name"]))]
    if not (hinted or texts):
        return None
    user_field = (hinted or texts)[0]
    payload: dict[str, str] = {}
    for item in inputs:
        name, kind = str(item["name"]), str(item.get("type", ""))
        if kind == "password":
            payload[name] = password
        elif item is user_field:
            payload[name] = user
        elif kind == "hidden":
            payload[name] = str(item.get("value", ""))[:4096]
    return payload


def limited(got: Fetched) -> str:
    """Why ``got`` shows a rate limit / lockout, or ``""``."""
    if got.status in (423, 429):
        return f"HTTP {got.status}"
    if "retry-after" in got.headers:
        return "a Retry-After header"
    match = _LIMITED.search(got.body[:200_000])
    return f"the message {match.group(0)!r}" if match else ""


async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
    """Up to 3 failed logins with a marked fake account; report if none was limited."""
    requested = ctx.params.get("attempts", MAX_ATTEMPTS)
    attempts = max(1, min(MAX_ATTEMPTS, requested if isinstance(requested, int) else 3))
    marker = probe_marker(ctx)
    user, password = f"{marker}@example.invalid", f"{marker}-wrong-password"
    login_page = target_path_url(ctx)

    statuses: list[int] = []
    action = ""
    for n in range(attempts):
        await navigate(page, ctx, login_page)
        form = login_form(await page_forms(page))
        if form is None:
            ctx.record_request({"url": login_page, "skipped": "no login form found"})
            return []
        action = str(form.get("action") or "")
        if not same_origin(action, ctx.target_url):
            # Posting credentials to another origin is out of scope (and out of policy).
            ctx.record_request({"url": login_page, "skipped": "login form posts off-origin"})
            return []
        payload = form_payload(form, user, password)
        if payload is None:
            ctx.record_request({"url": login_page, "skipped": "no username field"})
            return []
        got = await fetch(page, ctx, action, form=payload)
        if got is None:
            return []
        reason = limited(got)
        if reason:
            ctx.record_request({"url": action, "attempt": n + 1, "limited_by": reason})
            return []
        if got.status >= 500:
            return []  # the server is failing, not answering: nothing to conclude
        statuses.append(got.status)

    if len(statuses) < MAX_ATTEMPTS:
        return []  # fewer attempts than the bar: not enough evidence
    ctx.record_request({"url": action, "attempts": len(statuses), "limited_by": None})
    return [
        finding(
            check_id=CHECK_ID,
            title="No sign of login rate limiting after 3 failed attempts",
            severity="medium",
            url=action,
            evidence=[NETWORK_SUMMARY],
            reproduction=[
                f"Open {path_of(login_page)} and submit the login form with a non-existent "
                "account and a wrong password, three times",
                "Observe HTTP " + ", ".join(str(s) for s in statuses) + " with no 429, "
                "Retry-After, lockout message or CAPTCHA",
            ],
            impact="Without throttling, attackers can guess passwords or replay leaked "
            "credentials at high speed.",
            recommended_fix="Throttle failed logins per account and per IP (e.g. 5 per "
            "15 minutes with backoff), return 429 with Retry-After, and add CAPTCHA or MFA "
            "after repeated failures.",
            confidence=0.6,
        )
    ]
