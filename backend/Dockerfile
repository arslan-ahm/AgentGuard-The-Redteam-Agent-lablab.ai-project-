# Backend API + RQ worker image. Build context is the repo root (needs shared/contracts-py):
#   docker compose build backend
FROM ghcr.io/astral-sh/uv:0.11.9-python3.11-trixie-slim

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=never PYTHONUNBUFFERED=1
WORKDIR /app/backend

COPY shared/contracts-py /app/shared/contracts-py
COPY backend/pyproject.toml backend/uv.lock backend/.python-version ./
RUN uv sync --locked --no-dev --no-install-project

COPY backend/ ./
RUN uv sync --locked --no-dev \
    && useradd --create-home --uid 10001 agentguard \
    && chown -R agentguard /app/backend
USER agentguard

ENV PATH="/app/backend/.venv/bin:$PATH"
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"
# Create/upgrade the schema first (idempotent), then serve. Only this service migrates: the RQ
# worker image overrides CMD. Create a login afterwards: python -m app.db.seed <email> <password>
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers"]
