"""Secret redaction (brief 6.9): every format we promise to catch, prose left alone, and
linear time on hostile input. Secrets below are fake fixtures."""

from __future__ import annotations

import time
from typing import Any

import pytest

from app.policy.redaction import (
    REDACTED,
    is_secret_key,
    redact,
    redact_headers,
    redact_text,
)

JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("Authorization: Bearer abc123def456ghi789", "abc123def456ghi789"),
        ("authorization=Basic dXNlcjpwYXNzd29yZDE=", "dXNlcjpwYXNzd29yZDE="),
        ("sent Bearer 9f8e7d6c5b4a39281706 to api", "9f8e7d6c5b4a39281706"),
        (f"token in log: {JWT}", JWT),
        ("Cookie: sessionid=s3cr3tvalue; theme=dark", "s3cr3tvalue"),
        ("Set-Cookie: connect.sid=s%3Aabc.def; Path=/; HttpOnly", "s%3Aabc.def"),
        ("aws AKIAIOSFODNN7EXAMPLE used", "AKIAIOSFODNN7EXAMPLE"),
        ("gh token ghp_" + "a" * 36, "ghp_" + "a" * 36),
        ("pat github_pat_11ABCDEFG0123456789_abcdefghijklmnop", "github_pat_11ABCDEFG"),
        ("key sk-ant-api03-" + "x" * 40, "sk-ant-api03-"),
        ("key sk-proj-" + "y" * 30, "sk-proj-"),
        ("stripe sk_live_" + "4" * 24, "sk_live_"),
        ("slack xoxb-1234567890-abcdefghij", "xoxb-1234567890"),
        ("google AIza" + "B" * 35, "AIza" + "B" * 35),
        ("supabase sb_secret_" + "z" * 20, "sb_secret_"),
        ("db postgresql://admin:hunter2@db.internal:5432/app", "hunter2"),
        ("https://user:p4ss@example.com/x", "p4ss"),
        ("GET /reset?token=abcdef123456&lang=en", "abcdef123456"),
        ("callback?code=AUTHCODE987&state=x", "AUTHCODE987"),
        ("/download?X-Amz-Signature=deadbeef1234", "deadbeef1234"),
        ("form body: user=bob&password=hunter2&remember=1", "hunter2"),
        ('{"password": "hunter2", "user": "bob"}', "hunter2"),
        ("client_secret: 'abc-def-ghi'", "abc-def-ghi"),
        (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\nabc\n-----END RSA PRIVATE KEY-----",
            "MIIEpAIBAAKCAQEA",
        ),
    ],
)
def test_redact_text_removes_secret(text: str, secret: str) -> None:
    out = redact_text(text)
    assert secret not in out
    assert REDACTED in out


@pytest.mark.parametrize(
    "text",
    [
        "Basic authentication is supported.",
        "Use a bearer token in the header.",
        "The password reset page does not reveal whether an email exists.",
        "Missing Content-Security-Policy header",
        "https://shop.example.com/checkout?coupon=SAVE10&qty=2",
        "Traceback (most recent call last): File app.py line 3",
        "",
    ],
)
def test_redact_text_leaves_normal_text_alone(text: str) -> None:
    assert redact_text(text) == text


def test_redact_keeps_parameter_and_cookie_names() -> None:
    out = redact_text("GET /a?session_id=abc123&page=2")
    assert out == "GET /a?session_id=" + REDACTED + "&page=2"


def test_redact_url_credentials_keeps_host() -> None:
    assert redact_text("https://u:p@shop.example.com/") == f"https://{REDACTED}@shop.example.com/"


@pytest.mark.parametrize(
    "key",
    [
        "password",
        "Authorization",
        "set-cookie",
        "X-API-Key",
        "api_key",
        "db_password",
        "githubToken",
        "client_secret",
        "sessionid",
        "csrf_token",
        "private_key",
        "PIN",
    ],
)
def test_is_secret_key(key: str) -> None:
    assert is_secret_key(key)


@pytest.mark.parametrize("key", ["url", "status", "title", "author", "keyboard", "monkey"])
def test_is_not_secret_key(key: str) -> None:
    assert not is_secret_key(key)


def test_redact_nested_structures() -> None:
    data: dict[str, Any] = {
        "url": "https://shop.example.com/?token=abc12345",
        "headers": {"Authorization": "Bearer xyz", "Content-Type": "text/html"},
        "items": [{"password": "hunter2"}, "Cookie: a=b"],
        "status": 200,
        "empty_secret": "",
        "tuple": ("sk_live_" + "1" * 20,),
    }
    out = redact(data)
    assert out["url"] == "https://shop.example.com/?token=" + REDACTED
    assert out["headers"] == {"Authorization": REDACTED, "Content-Type": "text/html"}
    assert out["items"][0] == {"password": REDACTED}
    assert REDACTED in out["items"][1]
    assert out["status"] == 200
    assert out["empty_secret"] == ""  # nothing to hide: kept so evidence stays readable
    assert out["tuple"] == (REDACTED,)
    assert data["headers"]["Authorization"] == "Bearer xyz"  # input not mutated


def test_redact_survives_deep_nesting() -> None:
    deep: dict[str, object] = {}
    node = deep
    for _ in range(200):
        node["n"] = {}
        node = node["n"]  # type: ignore[assignment]
    redact(deep)  # no RecursionError


def test_redact_headers() -> None:
    out = redact_headers({"Cookie": "a=b", "Referer": "https://x.example/?token=abcd1234"})
    assert out == {"Cookie": REDACTED, "Referer": "https://x.example/?token=" + REDACTED}


@pytest.mark.parametrize(
    "unit",
    [
        "Bearer ",
        "bearer a1",
        "eyJ",
        "eyJa.",
        "://a:",
        "?token=",
        "password=",
        "Cookie: ",
        "-----BEGIN PRIVATE KEY-----",
        "AKIA",
        "sk-",
        "a" * 7 + " ",
    ],
)
def test_redact_text_is_linear_on_hostile_input(unit: str) -> None:
    def cpu(size: int) -> float:
        text = (unit * (size // len(unit) + 1))[:size]
        best = []
        for _ in range(3):
            t = time.process_time()
            redact_text(text)
            best.append(time.process_time() - t)
        return min(best)

    quarter, full = cpu(50_000), cpu(200_000)
    assert full < max(1.0, 10 * quarter), f"{quarter=:.3f} {full=:.3f}"
