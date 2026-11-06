"""Each deliberate flaw of the demo store must exist, or the demo scan would find nothing."""

from __future__ import annotations

import re

import pytest

from app import DEMO_PASSWORD, DEMO_USER, create_app


@pytest.fixture
def client():
    return create_app().test_client()


def test_home_has_broken_link_and_img_without_alt(client) -> None:
    body = client.get("/").get_data(as_text=True)
    assert 'href="/old-sale"' in body
    assert client.get("/old-sale").status_code == 404
    assert re.search(r"<img(?![^>]*\balt=)", body)


def test_products_are_seeded(client) -> None:
    body = client.get("/products").get_data(as_text=True)
    assert "Trail Backpack" in body and "Wool Socks" in body


def test_search_reflects_input_unescaped(client) -> None:
    body = client.get("/search?q=<b>agentguard-probe-1</b>").get_data(as_text=True)
    assert "<b>agentguard-probe-1</b>" in body


def test_contact_post_fails_with_500(client) -> None:
    assert client.get("/contact").status_code == 200
    resp = client.post("/contact", data={"email": "a@b.co", "message": "hi"})
    assert resp.status_code == 500


def test_checkout_post_500_with_python_stack_trace(client) -> None:
    resp = client.post("/checkout", data={"name": "x"})
    body = resp.get_data(as_text=True)
    assert resp.status_code == 500
    assert "Traceback (most recent call last)" in body
    assert "KeyError" in body


def test_login_demo_user_and_generic_failure(client) -> None:
    ok = client.post("/login", data={"email": DEMO_USER, "password": DEMO_PASSWORD})
    assert ok.status_code == 200 and "signed in" in ok.get_data(as_text=True)
    bad = client.post("/login", data={"email": DEMO_USER, "password": "wrong"})
    assert bad.status_code == 401 and "Login failed" in bad.get_data(as_text=True)


def test_login_has_no_rate_limit(client) -> None:
    codes = {
        client.post("/login", data={"email": DEMO_USER, "password": f"x{i}"}).status_code
        for i in range(10)
    }
    assert codes == {401}  # never 429


def test_password_reset_and_cart_work(client) -> None:
    assert client.post("/password-reset", data={"email": "a@b.co"}).status_code == 200
    assert "Trail Backpack" in client.get("/cart").get_data(as_text=True)


def test_admin_is_exposed_without_auth(client) -> None:
    resp = client.get("/admin")
    assert resp.status_code == 200 and "Admin panel" in resp.get_data(as_text=True)


def test_about_logs_console_error_and_loads_missing_asset(client) -> None:
    body = client.get("/about").get_data(as_text=True)
    assert "console.error('demo error')" in body
    assert client.get("/static/missing.js").status_code == 404


def test_no_security_headers(client) -> None:
    headers = {k.lower() for k in client.get("/").headers.keys()}
    for name in ("content-security-policy", "strict-transport-security", "x-frame-options"):
        assert name not in headers


def test_cookie_lacks_secure_httponly_samesite(client) -> None:
    cookie = client.get("/").headers["Set-Cookie"].lower()
    assert cookie.startswith("session=")
    for attr in ("secure", "httponly", "samesite"):
        assert attr not in cookie


def test_session_id_leaks_into_urls(client) -> None:
    body = client.get("/").get_data(as_text=True)
    assert re.search(r'href="/products\?sid=[0-9a-f]{16}"', body)
    assert client.get("/products?sid=abc123").get_data(as_text=True).count("sid=abc123") >= 3


def test_open_redirect(client) -> None:
    resp = client.get("/redirect?next=https://evil.example/")
    assert resp.status_code == 302
    assert resp.headers["Location"] == "https://evil.example/"
