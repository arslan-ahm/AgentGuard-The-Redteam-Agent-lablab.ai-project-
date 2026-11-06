"""FastAPI application entry point: ``uv run uvicorn app.main:app --reload``."""

from __future__ import annotations

from typing import Any

from agentguard_contracts import API_PREFIX, ErrorDetail, ErrorResponse
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.routes import router as api_router
from app.config import get_settings


def error_response(status_code: int, code: str, message: str) -> JSONResponse:
    """Build a response in the brief 5.8 error shape."""
    body = ErrorResponse(error=ErrorDetail(code=code, message=message))
    return JSONResponse(status_code=status_code, content=body.model_dump())


def create_app() -> FastAPI:
    """Create the app. Every error, including 404 and validation, uses the 5.8 error shape."""
    settings = get_settings()
    app = FastAPI(title="AgentGuard API", version="0.1.0")

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
            return error_response(exc.status_code, str(detail["code"]), str(detail["message"]))
        return error_response(exc.status_code, f"http_{exc.status_code}", str(detail))

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
