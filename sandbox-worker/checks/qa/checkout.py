"""qa.checkout: does the checkout page load and accept an order? (brief 3, 6.5)

Opens the checkout page (``params.path``, default ``/checkout``) and submits its order form
once with harmless marked values: probe name and address, an ``@example.invalid`` email and
**zeros** for card number, expiry and CVC. A checkout must refuse that cleanly (a validation
error), never crash, and never be an unreachable page. No real card number is ever sent, and
redirects are not followed, so no order can complete.
"""

from __future__ import annotations

from typing import Any

from checks.context import CheckContext
from checks.qa._common import (
    build_payload,
    default_path_url,
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
)

CHECK_ID = "qa.checkout"


def order_form(forms: list[dict[str, Any]], target_url: str) -> dict[str, Any] | None:
    """First same-origin POST form with fields and no password field."""
    for form in forms:
        if (
            is_post_form(form)
            and not has_password(form)
            and named_inputs(form)
            and same_origin(str(form.get("action") or ""), target_url)
        ):
            return form
    return None


async def run(page: Any, ctx: CheckContext) -> list[dict[str, Any]]:
    """Open checkout and submit the order form with probe data."""
    url, explicit = default_path_url(ctx, "/checkout")
    path = path_of(url)
    response = await safe_navigate(page, ctx, url)
    if response is None:
        return []
    shots = await screenshot_or_none(ctx, "checkout")
    evidence = [*shots, NETWORK_SUMMARY]

    if response.status >= 500 or (response.status == 404 and explicit):
        return [
            qa_finding(
                check_id=CHECK_ID,
                title=f"Checkout page {path} returns HTTP {response.status}",
                severity="high",
                url=url,
                evidence=evidence,
                reproduction=[
                    f"Open {path}",
                    f"Observe HTTP {response.status} instead of checkout",
                ],
                impact="Customers cannot buy anything: direct revenue loss.",
                recommended_fix="Fix the checkout route and alert on checkout errors.",
            )
        ]
    if response.status >= 400:
        return []  # no checkout page here (or it needs a cart or login): nothing to test

    form = order_form(await page_forms(page), ctx.target_url)
    if form is None:
        ctx.record_request({"url": url, "skipped": "no order form found"})
        return []
    action = str(form["action"])
    got = await fetch(page, ctx, action, form=build_payload(form, probe_marker(ctx)))
    if got is None or got.status < 500:
        return []
    return [
        qa_finding(
            check_id=CHECK_ID,
            title=f"Checkout fails on submit (HTTP {got.status})",
            severity="high",
            url=action,
            evidence=evidence,
            reproduction=[
                f"Open {path}",
                "Fill in the order form with test values and place the order",
                f"Observe HTTP {got.status} instead of a confirmation or a validation message",
            ],
            impact="Customers who reach checkout cannot complete a purchase: direct revenue loss.",
            recommended_fix="Reproduce with the same test values, fix the order handler, and "
            "return validation errors (4xx) instead of crashing. Add an alert on checkout 5xx.",
        )
    ]
