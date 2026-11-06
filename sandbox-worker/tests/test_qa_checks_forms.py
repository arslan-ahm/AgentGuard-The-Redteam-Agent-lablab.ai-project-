"""QA checks that submit forms: forms, login, password_reset, search, checkout.

Plus the contract run through ``runner.execute`` and the safety rules every probe must keep
(marked values, no real card numbers, no redirects followed, nothing off-origin).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from agentguard_contracts import SandboxTaskInput

import runner
from checks.qa import _common, checkout, forms, login, password_reset, search
from tests.qa_fakes import (
    TARGET,
    FakeAPIResponse,
    FakePage,
    FakeResponse,
    assert_contract,
    form,
    make_ctx,
    titles,
)

# --- helpers -------------------------------------------------------------------------


def crash_on_post(_: dict[str, str]) -> FakeAPIResponse:
    return FakeAPIResponse(500, body="Traceback (most recent call last):")


def crash_on_blank(payload: dict[str, str]) -> FakeAPIResponse:
    blank = all(v == "" for k, v in payload.items() if k != "csrf")
    return FakeAPIResponse(500 if blank else 200)


CONTACT = form(f"{TARGET}/contact", [("name", "text"), ("email", "email"), ("message", "textarea")])
LOGIN = form(f"{TARGET}/login", [("email", "email"), ("password", "password"), ("csrf", "hidden")])
RESET = form(f"{TARGET}/password-reset", [("email", "email")])
SEARCH = form(f"{TARGET}/search", [("q", "search")], method="get")
ORDER = form(
    f"{TARGET}/checkout",
    [
        ("full_name", "text"),
        ("email", "email"),
        ("address", "text"),
        ("card_number", "text"),
        ("expiry", "text"),
        ("cvv", "text"),
        ("csrf", "hidden"),
    ],
    values={"csrf": "tok123"},
)


# --- forms ---------------------------------------------------------------------------


async def test_forms_clean(tmp_path: Path) -> None:
    page = FakePage(forms=[CONTACT])
    assert await forms.run(page, make_ctx(tmp_path, page, path="/contact")) == []
    assert len(page.request.post_calls) == 2  # valid, then empty


async def test_forms_valid_submit_500_is_high_and_skips_empty_submit(tmp_path: Path) -> None:
    page = FakePage(forms=[CONTACT])
    page.request.posts[f"{TARGET}/contact"] = crash_on_post
    found = await forms.run(page, make_ctx(tmp_path, page, path="/contact"))
    assert titles(found) == ["Form posting to /contact fails (HTTP 500)"]
    assert found[0]["severity"] == "high"
    assert_contract(found, "qa.forms")
    assert len(page.request.post_calls) == 1


async def test_forms_empty_input_crash_is_medium(tmp_path: Path) -> None:
    page = FakePage(forms=[CONTACT])
    page.request.posts[f"{TARGET}/contact"] = crash_on_blank
    found = await forms.run(page, make_ctx(tmp_path, page, path="/contact"))
    assert titles(found) == ["Form posting to /contact crashes on empty input (HTTP 500)"]
    assert found[0]["severity"] == "medium"
    assert_contract(found, "qa.forms")


async def test_forms_dead_action_is_reported(tmp_path: Path) -> None:
    page = FakePage(forms=[CONTACT])
    page.request.posts[f"{TARGET}/contact"] = FakeAPIResponse(404)
    found = await forms.run(page, make_ctx(tmp_path, page))
    assert titles(found) == ["Form posting to /contact points nowhere (HTTP 404)"]


async def test_forms_skips_login_search_and_off_origin_forms(tmp_path: Path) -> None:
    off = form("https://evil.example.com/collect", [("email", "email")])
    page = FakePage(forms=[LOGIN, SEARCH, off])
    assert await forms.run(page, make_ctx(tmp_path, page)) == []
    assert page.request.post_calls == []


async def test_forms_probe_values_are_marked_and_harmless(tmp_path: Path) -> None:
    page = FakePage(forms=[CONTACT])
    await forms.run(page, make_ctx(tmp_path, page, probe_marker="agentguard-probe-test1"))
    valid, blank = (call[1] for call in page.request.post_calls)
    assert valid["email"] == "agentguard-probe-test1@example.invalid"
    assert valid["message"] == "agentguard-probe-test1"
    assert set(blank.values()) == {""}


# --- login ---------------------------------------------------------------------------


async def test_login_clean(tmp_path: Path) -> None:
    page = FakePage(forms=[LOGIN])
    page.request.posts[f"{TARGET}/login"] = FakeAPIResponse(401)
    assert await login.run(page, make_ctx(tmp_path, page)) == []
    first = page.request.post_calls[0][1]
    assert first["email"].endswith("@example.invalid") and "agentguard-probe-" in first["email"]
    assert len(page.request.post_calls) == 2  # fake account, then empty fields


async def test_login_crash_on_bad_credentials_is_high(tmp_path: Path) -> None:
    page = FakePage(forms=[LOGIN])
    page.request.posts[f"{TARGET}/login"] = crash_on_post
    found = await login.run(page, make_ctx(tmp_path, page, path="/login"))
    assert titles(found) == ["Login crashes on invalid credentials (HTTP 500)"]
    assert found[0]["severity"] == "high"
    assert_contract(found, "qa.login")


async def test_login_accepting_a_fake_account_is_flagged_low_confidence(tmp_path: Path) -> None:
    page = FakePage(forms=[LOGIN])
    page.request.posts[f"{TARGET}/login"] = FakeAPIResponse(302, {"Location": "/account"})
    found = await login.run(page, make_ctx(tmp_path, page))
    assert titles(found) == ["Login appears to accept a non-existent account"]
    assert found[0]["severity"] == "critical" and found[0]["confidence"] < 0.5
    assert_contract(found, "qa.login")


async def test_login_redirect_back_to_login_is_fine(tmp_path: Path) -> None:
    page = FakePage(forms=[LOGIN])
    page.request.posts[f"{TARGET}/login"] = FakeAPIResponse(302, {"Location": "/login?error=1"})
    assert await login.run(page, make_ctx(tmp_path, page)) == []


async def test_login_page_errors_and_absence(tmp_path: Path) -> None:
    broken = FakePage(routes={f"{TARGET}/login": FakeResponse(500)})
    found = await login.run(broken, make_ctx(tmp_path, broken))
    assert titles(found) == ["Login page /login returns HTTP 500"]
    assert_contract(found, "qa.login")

    missing = FakePage(routes={f"{TARGET}/login": FakeResponse(404)})
    assert await login.run(missing, make_ctx(tmp_path, missing)) == []  # not applicable
    explicit = await login.run(missing, make_ctx(tmp_path, missing, path="/login"))
    assert titles(explicit) == ["Login page /login returns HTTP 404"]


async def test_login_skips_off_origin_form(tmp_path: Path) -> None:
    off = form("https://auth.example.net/login", [("email", "email"), ("pw", "password")])
    page = FakePage(forms=[off])
    assert await login.run(page, make_ctx(tmp_path, page)) == []
    assert page.request.post_calls == []


# --- password_reset ------------------------------------------------------------------


async def test_password_reset_clean_uses_fake_and_malformed_addresses(tmp_path: Path) -> None:
    page = FakePage(forms=[RESET])
    assert await password_reset.run(page, make_ctx(tmp_path, page)) == []
    good, bad = (call[1] for call in page.request.post_calls)
    assert good["email"].endswith("@example.invalid")
    assert bad["email"] == "not-an-email"


async def test_password_reset_500_is_high(tmp_path: Path) -> None:
    page = FakePage(forms=[RESET])
    page.request.posts[f"{TARGET}/password-reset"] = crash_on_post
    found = await password_reset.run(page, make_ctx(tmp_path, page, path="/password-reset"))
    assert titles(found) == ["Password reset fails for an unknown address (HTTP 500)"]
    assert found[0]["severity"] == "high"
    assert_contract(found, "qa.password_reset")


async def test_password_reset_malformed_address_crash_is_medium(tmp_path: Path) -> None:
    def handler(payload: dict[str, str]) -> FakeAPIResponse:
        return FakeAPIResponse(500 if payload["email"] == "not-an-email" else 200)

    page = FakePage(forms=[RESET])
    page.request.posts[f"{TARGET}/password-reset"] = handler
    found = await password_reset.run(page, make_ctx(tmp_path, page))
    assert titles(found) == ["Password reset crashes on a malformed address (HTTP 500)"]
    assert found[0]["severity"] == "medium"


async def test_password_reset_absent_is_not_a_finding_but_explicit_404_is(tmp_path: Path) -> None:
    routes: dict[str, FakeResponse | Exception] = {
        f"{TARGET}{p}": FakeResponse(404) for p in ("/password-reset", "/forgot-password")
    }
    page = FakePage(routes=routes)
    assert await password_reset.run(page, make_ctx(tmp_path, page)) == []
    found = await password_reset.run(page, make_ctx(tmp_path, page, path="/password-reset"))
    assert titles(found) == ["Password reset page /password-reset returns HTTP 404"]
    assert_contract(found, "qa.password_reset")


async def test_password_reset_explicit_page_without_form(tmp_path: Path) -> None:
    page = FakePage(forms=[])
    found = await password_reset.run(page, make_ctx(tmp_path, page, path="/forgot"))
    assert titles(found) == ["Password reset page /forgot has no email form"]


# --- search --------------------------------------------------------------------------


async def test_search_clean(tmp_path: Path) -> None:
    page = FakePage(forms=[SEARCH])
    assert (
        await search.run(page, make_ctx(tmp_path, page, probe_marker="agentguard-probe-s1")) == []
    )
    assert page.request.get_calls == [
        f"{TARGET}/search?q=agentguard-probe-s1",
        f"{TARGET}/search?q=",
    ]


async def test_search_500_is_high(tmp_path: Path) -> None:
    page = FakePage(forms=[SEARCH])
    page.request.default_status = 500
    found = await search.run(page, make_ctx(tmp_path, page))
    assert titles(found) == ["Search fails with HTTP 500"]
    assert found[0]["severity"] == "high"
    assert_contract(found, "qa.search")
    assert len(page.request.get_calls) == 1


async def test_search_empty_query_crash_is_medium(tmp_path: Path) -> None:
    page = FakePage(forms=[SEARCH])
    page.request.gets[f"{TARGET}/search?q="] = FakeAPIResponse(500)
    found = await search.run(page, make_ctx(tmp_path, page))
    assert titles(found) == ["Search crashes on an empty query (HTTP 500)"]
    assert found[0]["severity"] == "medium"


async def test_search_without_form_reports_nothing(tmp_path: Path) -> None:
    page = FakePage(forms=[CONTACT])
    assert await search.run(page, make_ctx(tmp_path, page)) == []
    assert page.request.get_calls == []


# --- checkout ------------------------------------------------------------------------


async def test_checkout_clean_and_never_sends_a_real_card(tmp_path: Path) -> None:
    page = FakePage(forms=[ORDER])
    page.request.posts[f"{TARGET}/checkout"] = FakeAPIResponse(422)
    assert await checkout.run(page, make_ctx(tmp_path, page)) == []
    assert page.visited == [f"{TARGET}/checkout"]
    sent = page.request.post_calls[0][1]
    assert sent["card_number"] == "0000000000000000"
    assert sent["cvv"] == "000" and sent["expiry"] == "12/34"
    assert sent["csrf"] == "tok123"
    assert sent["email"].endswith("@example.invalid")


async def test_checkout_500_with_stack_trace_is_high(tmp_path: Path) -> None:
    page = FakePage(forms=[ORDER])
    page.request.posts[f"{TARGET}/checkout"] = crash_on_post
    found = await checkout.run(page, make_ctx(tmp_path, page, path="/checkout"))
    assert titles(found) == ["Checkout fails on submit (HTTP 500)"]
    assert found[0]["severity"] == "high"
    assert_contract(found, "qa.checkout")


async def test_checkout_page_errors(tmp_path: Path) -> None:
    broken = FakePage(routes={f"{TARGET}/checkout": FakeResponse(503)})
    found = await checkout.run(broken, make_ctx(tmp_path, broken))
    assert titles(found) == ["Checkout page /checkout returns HTTP 503"]
    assert_contract(found, "qa.checkout")

    missing = FakePage(routes={f"{TARGET}/checkout": FakeResponse(404)})
    assert await checkout.run(missing, make_ctx(tmp_path, missing)) == []


async def test_checkout_without_form_reports_nothing(tmp_path: Path) -> None:
    page = FakePage(forms=[])
    assert await checkout.run(page, make_ctx(tmp_path, page)) == []


# --- shared helpers ------------------------------------------------------------------


def test_build_payload_never_uses_real_looking_card_numbers() -> None:
    payload = _common.build_payload(ORDER, "agentguard-probe-x")
    assert all("4242" not in v and "4111" not in v for v in payload.values())


def test_build_payload_radio_and_checkbox() -> None:
    f = form(
        "/x",
        [("plan", "radio"), ("plan", "radio"), ("terms", "checkbox"), ("go", "submit")],
        values={"plan": "basic"},
    )
    assert _common.build_payload(f, "m") == {"plan": "basic", "terms": "on"}
    assert _common.build_payload(f, "m", blank=True) == {}


def test_redact_masks_secrets_and_truncates() -> None:
    out = _common.redact("login failed: Authorization: Bearer abcdef123456 " + "x" * 500)
    assert "abcdef123456" not in out and len(out) <= 320


# --- contract through the runner -----------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "pages_load",
        "links_assets",
        "forms",
        "login",
        "password_reset",
        "search",
        "checkout",
        "console_network_errors",
        "accessibility",
    ],
)
def test_runner_can_load_every_qa_check(name: str) -> None:
    module = runner.load_check(f"qa.{name}")
    assert module.CHECK_ID == f"qa.{name}"


async def test_runner_execute_writes_valid_result_for_a_failing_checkout(tmp_path: Path) -> None:
    page = FakePage(forms=[ORDER])
    page.request.posts[f"{TARGET}/checkout"] = crash_on_post
    task: dict[str, Any] = {
        "scan_id": "11111111-1111-4111-8111-111111111111",
        "target_url": TARGET,
        "task": {
            "task_id": "t1",
            "check_id": "qa.checkout",
            "description": "Place an order",
            "params": {"path": "/checkout"},
            "timeout_s": 30,
        },
    }
    task_input = SandboxTaskInput.model_validate(task)
    result, code = await runner.execute(
        task_input, runner.load_check("qa.checkout"), page, tmp_path
    )
    assert code == 0 and result.status.value == "failed"
    assert result.findings[0].check_id == "qa.checkout"
    assert result.findings[0].category.value == "qa"
    summary = json.loads((tmp_path / "network_summary.json").read_text())
    assert any(entry.get("status") == 500 for entry in summary)
    assert (tmp_path / "screenshots" / "checkout.png").exists()
