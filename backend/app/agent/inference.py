"""Vultr Serverless Inference client (brief 6.3): OpenAI-compatible chat completions.

- hard per-call timeout and a bounded number of retries with backoff, only on transient
  failures (connection, timeout, 429, 5xx); auth or bad-request errors fail at once;
- the API key lives in ``SecretStr`` settings and is never logged;
- callers get plain text or :class:`InferenceError`, so a planner can always fall back.

``ChatModel`` is the seam tests (and any other provider) plug into.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, Protocol

import openai
from openai import AsyncOpenAI

from app.config import Settings

log = logging.getLogger(__name__)

DEFAULT_TIMEOUT_S = 20.0
DEFAULT_RETRIES = 2
DEFAULT_MAX_TOKENS = 1200
MAX_RESPONSE_CHARS = 20_000

_TRANSIENT: tuple[type[BaseException], ...] = (
    openai.APIConnectionError,  # includes APITimeoutError
    openai.RateLimitError,
    openai.InternalServerError,
    TimeoutError,  # asyncio.wait_for
)


class InferenceError(RuntimeError):
    """The model could not produce an answer (not configured, failed, timed out, empty)."""


class ChatModel(Protocol):
    async def complete(self, system: str, user: str) -> str:
        """One chat completion. Raises ``InferenceError`` on any failure."""
        ...


class VultrInferenceClient:
    """Chat completions against ``VULTR_INFERENCE_BASE_URL`` with ``VULTR_INFERENCE_MODEL``."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        timeout_s: float = DEFAULT_TIMEOUT_S,
        retries: int = DEFAULT_RETRIES,
        backoff_s: float = 0.5,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        client: Any | None = None,
    ) -> None:
        if not (base_url and api_key and model):
            raise InferenceError("inference needs base URL, API key and model")
        self.model = model
        self.retries = max(0, retries)
        self.backoff_s = backoff_s
        self.max_tokens = max_tokens
        # The SDK's own retries are off: ours are bounded and only for transient errors.
        self._client = client or AsyncOpenAI(
            base_url=base_url, api_key=api_key, timeout=timeout_s, max_retries=0
        )
        self._timeout_s = timeout_s

    @classmethod
    def from_settings(cls, settings: Settings) -> VultrInferenceClient | None:
        """A client when ``VULTR_INFERENCE_*`` are all set, else None (use the fallback)."""
        if not (settings.inference_configured and settings.vultr_inference_model):
            return None
        return cls(
            base_url=settings.vultr_inference_base_url,
            api_key=settings.vultr_inference_api_key.get_secret_value(),
            model=settings.vultr_inference_model,
        )

    async def complete(self, system: str, user: str) -> str:
        last: BaseException | None = None
        for attempt in range(self.retries + 1):
            try:
                response = await asyncio.wait_for(
                    self._client.chat.completions.create(
                        model=self.model,
                        messages=[
                            {"role": "system", "content": system},
                            {"role": "user", "content": user},
                        ],
                        temperature=0.1,
                        max_tokens=self.max_tokens,
                    ),
                    timeout=self._timeout_s + 5,  # belt and braces over the SDK timeout
                )
                text = response.choices[0].message.content if response.choices else None
                if not text or not text.strip():
                    raise InferenceError("empty answer from the model")
                return str(text)[:MAX_RESPONSE_CHARS]
            except _TRANSIENT as exc:
                last = exc
                log.warning(
                    "inference attempt %d/%d failed: %s",
                    attempt + 1,
                    self.retries + 1,
                    type(exc).__name__,
                )
                if attempt < self.retries:
                    await asyncio.sleep(self.backoff_s * (2**attempt))
            except InferenceError:
                raise
            except openai.OpenAIError as exc:  # auth, bad request, not found: retrying won't help
                raise InferenceError(f"inference failed: {type(exc).__name__}") from exc
        raise InferenceError(f"inference failed after retries: {type(last).__name__}") from last


_FENCED = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL | re.IGNORECASE)


def extract_json(text: str) -> Any:
    """The JSON object in a model answer (bare, or inside a ``` fence). Raises ValueError."""
    match = _FENCED.search(text)
    body = match.group(1) if match else text
    start, end = body.find("{"), body.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("no JSON object in the answer")
    try:
        return json.loads(body[start : end + 1])
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON: {exc.msg} at char {exc.pos}") from exc
