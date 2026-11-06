"""Runtime configuration, read from environment variables (brief 5.12). Never hardcode values."""

from __future__ import annotations

from functools import lru_cache

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Environment-backed settings. Names match ``.env.example`` exactly."""

    # Repo-root .env (the documented location) first; a backend/.env overrides it if present.
    # Real environment variables (Docker Compose) always win over both files.
    model_config = SettingsConfigDict(env_file=("../.env", ".env"), extra="ignore")

    database_url: str = "sqlite:///./agentguard.db"
    redis_url: str = "redis://localhost:6379/0"
    secret_key: SecretStr = SecretStr("")

    vultr_inference_base_url: str = ""
    vultr_inference_api_key: SecretStr = SecretStr("")
    vultr_inference_model: str = ""

    sandbox_image: str = "agentguard-sandbox:local"
    sandbox_cpu_limit: str = "1.0"
    sandbox_mem_limit: str = "1g"
    sandbox_timeout_s: int = 120

    allowed_origins: str = "http://localhost:5173"
    github_token: SecretStr | None = None
    public_base_url: str = "http://localhost:8000"

    @property
    def allowed_origins_list(self) -> list[str]:
        """``ALLOWED_ORIGINS`` as a list (comma-separated in the env)."""
        return [o.strip() for o in self.allowed_origins.split(",") if o.strip()]

    @property
    def inference_configured(self) -> bool:
        """True when Vultr Serverless Inference credentials are present.

        When False the planner must use its deterministic fallback plan (brief 6.3).
        """
        return bool(
            self.vultr_inference_base_url and self.vultr_inference_api_key.get_secret_value()
        )


@lru_cache
def get_settings() -> Settings:
    """Cached settings instance (use as a FastAPI dependency)."""
    return Settings()
