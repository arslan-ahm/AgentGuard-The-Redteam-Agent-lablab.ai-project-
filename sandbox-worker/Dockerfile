# Disposable Playwright sandbox (brief 6.4). Owner: Arslan.
# Build context is the repo root:  docker compose build sandbox
# The image tag MUST match the playwright version pinned in pyproject.toml.
FROM mcr.microsoft.com/playwright/python:v1.64.0-noble

COPY --from=ghcr.io/astral-sh/uv:0.11.9 /uv /usr/local/bin/uv
# The base image ships Python 3.12; the brief pins 3.11, so uv installs it under /opt
# (readable by the non-root user) at build time. Nothing is downloaded at run time.
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_PYTHON_INSTALL_DIR=/opt/python PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
WORKDIR /app/sandbox-worker

COPY shared/contracts-py /app/shared/contracts-py
COPY sandbox-worker/pyproject.toml sandbox-worker/uv.lock sandbox-worker/.python-version ./
RUN uv sync --locked --no-dev --no-install-project
COPY sandbox-worker/ ./
RUN chmod -R a+rX /opt/python /opt/venv /app

# Non-root. The launcher adds: --rm, --read-only + tmpfs, --cap-drop=ALL,
# --security-opt=no-new-privileges, cpu/memory/pids limits, /in:ro, /out, egress rules.
USER pwuser
ENTRYPOINT ["/opt/venv/bin/python", "runner.py"]
