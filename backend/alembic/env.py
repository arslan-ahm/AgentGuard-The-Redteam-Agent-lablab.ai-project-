"""Alembic environment. The URL comes from app settings (DATABASE_URL), never from alembic.ini."""

from __future__ import annotations

from logging.config import fileConfig

from sqlalchemy import create_engine, pool

from alembic import context
from app.config import get_settings
from app.db import models  # noqa: F401  (registers all tables on Base.metadata)
from app.db.session import Base

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata
_url = get_settings().database_url


def run_migrations_offline() -> None:
    """Emit SQL without a live connection."""
    context.configure(
        url=_url,
        target_metadata=target_metadata,
        literal_binds=True,
        render_as_batch=_url.startswith("sqlite"),
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations against the configured database."""
    engine = create_engine(_url, poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=_url.startswith("sqlite"),
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
