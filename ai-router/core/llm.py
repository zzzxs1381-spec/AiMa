from __future__ import annotations

import logging
from typing import Any

import requests

logger = logging.getLogger(__name__)

OPENROUTER_API_URL = "https://openrouter.ai/api/v1/chat/completions"

DEFAULT_FALLBACK_CHAIN = [
    "openai/gpt-4o",
    "anthropic/claude-3-opus",
    "google/gemini-2.0-flash",
    "openai/gpt-4o-mini",
]


class LLMError(Exception):
    """Raised when an LLM request fails."""


class LLM:
    """Wrapper around OpenRouter API with fallback chain support."""

    def __init__(
        self,
        api_key: str,
        fallback_chain: list[str] | None = None,
        timeout: int = 60,
        temperature: float = 0.2,
    ) -> None:
        self.api_key = api_key
        self.fallback_chain = list(fallback_chain or DEFAULT_FALLBACK_CHAIN)
        self.timeout = timeout
        self.temperature = temperature

    @classmethod
    def from_config(cls, api_key: str) -> LLM:
        """Build an LLM using fallback_chain/defaults from config/models.yaml."""
        from core.config import models_config

        cfg = models_config()
        defaults = cfg.get("defaults", {}) or {}
        return cls(
            api_key=api_key,
            fallback_chain=cfg.get("fallback_chain") or None,
            timeout=int(defaults.get("timeout", 60)),
            temperature=float(defaults.get("temperature", 0.2)),
        )

    def call(self, model: str, prompt: str, temperature: float | None = None) -> str:
        """Call a specific model; if it fails, fall back through the rest of the chain."""
        try:
            return self._request(model, prompt, temperature)
        except LLMError as exc:
            logger.warning("Model %s failed (%s), using fallback chain", model, exc)
            chain = [m for m in self.fallback_chain if m != model]
            if not chain:
                raise
            return self._chain(chain, prompt, temperature, first_error=f"{model}: {exc}")

    def fallback_call(self, prompt: str, temperature: float | None = None) -> str:
        """Try each model in the fallback chain until one succeeds."""
        return self._chain(self.fallback_chain, prompt, temperature)

    def _chain(
        self, chain: list[str], prompt: str, temperature: float | None, first_error: str | None = None
    ) -> str:
        errors: list[str] = [first_error] if first_error else []
        for model in chain:
            try:
                return self._request(model, prompt, temperature)
            except LLMError as exc:
                logger.warning("Model %s failed: %s", model, exc)
                errors.append(f"{model}: {exc}")
        raise LLMError(
            "All models in fallback chain failed:\n" + "\n".join(errors)
        )

    def _request(self, model: str, prompt: str, temperature: float | None = None) -> str:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload: dict[str, Any] = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": self.temperature if temperature is None else temperature,
        }

        try:
            response = requests.post(
                OPENROUTER_API_URL,
                headers=headers,
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise LLMError(f"Request to {model} failed: {exc}") from exc

        try:
            data = response.json()
        except ValueError as exc:
            raise LLMError(
                f"Invalid JSON response from {model}: {response.text[:200]}"
            ) from exc

        if isinstance(data, dict) and data.get("error"):
            raise LLMError(f"{model} returned error: {data['error']}")
        try:
            content = data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as exc:
            raise LLMError(
                f"Unexpected response structure from {model}: {str(data)[:300]}"
            ) from exc
        if not content:
            raise LLMError(f"Empty response from {model}")
        return content
