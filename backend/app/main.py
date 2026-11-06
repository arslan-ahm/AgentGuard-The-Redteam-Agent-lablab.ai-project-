"""FastAPI application entry point: ``uv run uvicorn app.main:app --reload``."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from typing import Any

from agentguard_contracts import API_PREFIX, ErrorDetail, ErrorResponse
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.routes import router as api_router
from app.config import get_settings
from app.orchestrator.orchestrator import Orchestrator
from app.orchestrator.queue import build_queue
from app.orchestrator.services import Services, build_services


def error_response(
    status_code: int, code: str, message: str, headers: Mapping[str, str] | None = None
) -> JSONResponse:
    """Build a response in the brief 5.8 error shape (keeps headers such as Retry-After)."""
    body = ErrorResponse(error=ErrorDetail(code=code, message=message))
    return JSONResponse(status_code=status_code, content=body.model_dump(), headers=headers)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Build the real services at startup unless a test injected its own."""
    if getattr(app.state, "services", None) is None:
        services = build_services()
        orchestrator = Orchestrator(services)
        services.queue = build_queue(get_settings().redis_url, orchestrator.run_scan)
        # A worker that died mid-scan leaves it active forever: fail those scans now.
        await orchestrator.fail_stale_scans()
        app.state.services = services
    yield


def create_app(services: Services | None = None) -> FastAPI:
    """Create the app. Every error, including 404 and validation, uses the 5.8 error shape.

    ``services`` is for tests; in production the lifespan builds them from the environment.
    """
    settings = get_settings()
    app = FastAPI(title="AgentGuard API", version="0.1.0", lifespan=_lifespan)
    app.state.services = services

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins_list,
        allow_methods=["GET", "POST"],
        allow_headers=["Authorization", "Content-Type"],
    )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        detail: Any = exc.detail
        if isinstance(detail, dict) and {"code", "message"} <= detail.keys():
            return error_response(
                exc.status_code, str(detail["code"]), str(detail["message"]), exc.headers
            )
        return error_response(exc.status_code, f"http_{exc.status_code}", str(detail), exc.headers)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
        first = exc.errors()[0] if exc.errors() else {}
        where = ".".join(str(p) for p in first.get("loc", ()))
        message = f"{where}: {first.get('msg', 'invalid request')}" if where else "invalid request"
        return error_response(422, "validation_error", message)

    @app.get("/healthz", tags=["ops"])
    async def healthz() -> dict[str, str]:
        """Liveness probe used by Docker Compose and the reverse proxy."""
        return {"status": "ok"}

    app.include_router(api_router, prefix=API_PREFIX)
    return app


app = create_app()
