"""AgentGuard demo store: a DELIBERATELY FLAWED shop used only as the demo scan target.

Owner: Sohaib (brief 6.5, SUBMISSION_PACK item 7). Every flaw here is on purpose and listed in
README.md with the check that should find it. Never deploy this publicly except as the demo
target, and never put real data or real secrets in it.

Run: ``uv run python app.py`` (listens on 127.0.0.1:5050; override with HOST / PORT).
"""

from __future__ import annotations

import json
import os
import secrets
import traceback
from html import escape
from pathlib import Path

from flask import Flask, Response, redirect, request
from werkzeug.exceptions import HTTPException

SEED = Path(__file__).resolve().parent / "seed" / "products.json"
PRODUCTS: list[dict[str, object]] = json.loads(SEED.read_text(encoding="utf-8"))

# Demo-only login. Not a secret: it is documented in README.md on purpose.
DEMO_USER = "demo@example.com"
DEMO_PASSWORD = "demo-pass"  # noqa: S105

# 1x1 transparent GIF, inlined so the page has an <img> without needing a network request.
_PIXEL = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"


def _page(title: str, body: str, *, sid: str = "") -> str:
    """Tiny HTML shell. Navigation links carry ``?sid=`` (FLAW: session id in the URL)."""
    q = f"?sid={sid}" if sid else ""
    nav = (
        f'<a href="/{q}">Home</a> | <a href="/products{q}">Products</a> | '
        f'<a href="/cart{q}">Cart</a> | <a href="/login{q}">Login</a> | '
        f'<a href="/contact{q}">Contact</a> | <a href="/about{q}">About</a>'
    )
    return (
        f"<!doctype html><html lang=en><head><meta charset=utf-8><title>{title}</title></head>"
        f"<body><nav>{nav}</nav><main>{body}</main></body></html>"
    )


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["PROPAGATE_EXCEPTIONS"] = False  # our handler renders the trace instead

    def current_sid() -> str:
        return request.args.get("sid") or request.cookies.get("session") or secrets.token_hex(8)

    def html(title: str, body: str, status: int = 200) -> Response:
        """Response that sets the session cookie WITHOUT Secure, HttpOnly or SameSite (FLAW)."""
        sid = current_sid()
        resp = Response(_page(title, body, sid=sid), status=status, mimetype="text/html")
        resp.set_cookie("session", sid)
        return resp

    # FLAW: no Content-Security-Policy, Strict-Transport-Security or X-Frame-Options anywhere.

    @app.get("/")
    def home() -> Response:
        return html(
            "Demo Store",
            "<h1>Demo Store</h1>"
            f'<img src="{_PIXEL}" width=40 height=40>'  # FLAW: no alt text
            '<p><a href="/old-sale">Summer sale</a> (broken link)</p>'
            '<p><a href="/redirect?next=/products">Shop now</a></p>',
        )

    @app.get("/products")
    def products() -> Response:
        items = "".join(
            f"<li>{escape(str(p['name']))} - ${p['price']} ({escape(str(p['description']))})</li>"
            for p in PRODUCTS
        )
        return html("Products", f"<h1>Products</h1><ul>{items}</ul>")

    @app.get("/search")
    def search() -> Response:
        q = request.args.get("q", "")
        form = "<form method=get action=/search><input name=q><button>Search</button></form>"
        # FLAW: the query is echoed back unescaped (reflected input).
        return html("Search", f"<h1>Search</h1>{form}<p>Results for: {q}</p>")

    @app.route("/contact", methods=["GET", "POST"])
    def contact() -> Response:
        if request.method == "POST":
            _send_mail(request.form)  # FLAW: always fails with HTTP 500
        form = (
            "<form method=post action=/contact>"
            "<input name=email type=email placeholder=Email>"  # FLAW: no <label>s
            "<textarea name=message placeholder=Message></textarea>"
            "<button>Send</button></form>"
        )
        return html("Contact", f"<h1>Contact us</h1>{form}")

    @app.route("/login", methods=["GET", "POST"])
    def login() -> Response:
        if request.method == "POST":
            ok = (
                request.form.get("email") == DEMO_USER
                and request.form.get("password") == DEMO_PASSWORD
            )
            if ok:
                return html("Welcome", "<h1>Welcome back</h1><p>You are signed in.</p>")
            # FLAW: no rate limit or lockout on repeated failures.
            return html("Login", "<h1>Login</h1><p>Login failed.</p>", status=401)
        form = (
            "<form method=post action=/login>"
            "<label>Email <input name=email type=email></label>"
            "<label>Password <input name=password type=password></label>"
            "<button>Log in</button></form>"
        )
        return html("Login", f"<h1>Login</h1>{form}")

    @app.route("/password-reset", methods=["GET", "POST"])
    def password_reset() -> Response:
        if request.method == "POST":
            return html(
                "Reset", "<h1>Check your email</h1><p>If the account exists, we sent a link.</p>"
            )
        form = (
            "<form method=post action=/password-reset>"
            "<label>Email <input name=email type=email></label><button>Reset</button></form>"
        )
        return html("Reset password", f"<h1>Reset password</h1>{form}")

    @app.get("/cart")
    def cart() -> Response:
        first = PRODUCTS[0]
        body = (
            f"<h1>Cart</h1><p>1 x {escape(str(first['name']))} - ${first['price']}</p>"
            "<form method=get action=/checkout><button>Checkout</button></form>"
        )
        return html("Cart", body)

    @app.route("/checkout", methods=["GET", "POST"])
    def checkout() -> Response:
        if request.method == "POST":
            _charge(request.form)  # FLAW: always fails with HTTP 500 and a stack trace
        form = (
            "<form method=post action=/checkout>"
            "<label>Name <input name=name></label>"
            "<label>Card <input name=card value=4242424242424242></label>"
            "<button>Pay now</button></form>"
        )
        return html("Checkout", f"<h1>Checkout</h1>{form}")

    @app.get("/admin")
    def admin() -> Response:
        # FLAW: admin page with no authentication at all.
        return html("Admin", "<h1>Admin panel</h1><p>Orders, users, settings. No login needed.</p>")

    @app.get("/about")
    def about() -> Response:
        body = (
            "<h1>About</h1><p>Opinionated gear for the outdoors.</p>"
            "<script src=/static/missing.js></script>"  # FLAW: 404 asset
            "<script>console.error('demo error');</script>"  # FLAW: console error
        )
        return html("About", body)

    @app.get("/redirect")
    def open_redirect() -> Response:
        # FLAW: redirects anywhere, no allow-list.
        return redirect(request.args.get("next", "/"))

    @app.errorhandler(Exception)
    def on_error(exc: Exception) -> Response | HTTPException:
        if isinstance(exc, HTTPException):
            return exc
        # FLAW: "DEBUG is on": the full Python traceback goes to the visitor.
        trace = escape(traceback.format_exc())
        return html("Server Error", f"<h1>Internal Server Error</h1><pre>{trace}</pre>", 500)

    return app


def _send_mail(form: object) -> None:
    raise ConnectionRefusedError("SMTP server mail.internal.example:25 refused the connection")


def _charge(form: object) -> None:
    gateway = {"currency": "USD"}
    gateway["merchant_id"]  # noqa: B018 - raises KeyError on purpose


app = create_app()

if __name__ == "__main__":
    app.run(
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "5050")),
        debug=False,
    )
