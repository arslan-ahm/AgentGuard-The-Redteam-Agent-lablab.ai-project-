"""Create or update an API user: ``uv run python -m app.db.seed <email> <password>``.

The password comes from the command line (or ``AGENTGUARD_SEED_PASSWORD``) and is stored only
as a salted scrypt hash. Run it after ``alembic upgrade head``.
"""

from __future__ import annotations

import os
import sys

from sqlalchemy import select

from app.api.auth import hash_password
from app.db.models import User
from app.db.session import SessionLocal


def upsert_user(email: str, password: str) -> str:
    """Insert the user or replace the password. Returns ``created`` or ``updated``."""
    email = email.strip().lower()
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == email))
        if user is None:
            db.add(User(email=email, password_hash=hash_password(password)))
            outcome = "created"
        else:
            user.password_hash = hash_password(password)
            outcome = "updated"
        db.commit()
    return outcome


def main(argv: list[str]) -> int:
    if len(argv) < 2 or not (len(argv) > 2 or os.environ.get("AGENTGUARD_SEED_PASSWORD")):
        print("usage: python -m app.db.seed <email> <password>", file=sys.stderr)
        return 2
    password = argv[2] if len(argv) > 2 else os.environ["AGENTGUARD_SEED_PASSWORD"]
    if len(password) < 8:
        print("password must be at least 8 characters", file=sys.stderr)
        return 2
    print(f"user {argv[1].strip().lower()}: {upsert_user(argv[1], password)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
