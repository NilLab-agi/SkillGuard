"""Choose a reviewer from settings."""

from __future__ import annotations

from skillguard.config import Settings
from skillguard.providers.base import Reviewer


def build_reviewer(settings: Settings) -> Reviewer:
    """Build the reviewer for the configured provider.

    The backend is imported lazily on purpose: ``langchain-openai`` lives in the
    optional ``llm`` extra, and the static scanner has to work without it.
    Only one provider exists by design — it drives OpenAI, Ollama, vLLM,
    OpenRouter and most gateways through ``base_url``.
    """
    try:
        from skillguard.providers.openai_compat import OpenAICompatReviewer
    except ImportError as exc:  # pragma: no cover - depends on install extras
        raise RuntimeError(
            "LLM review needs the optional 'llm' extra: "
            "run 'uv sync --extra llm' (or 'pip install \"skillguard[llm]\"')"
        ) from exc

    return OpenAICompatReviewer(settings)


def is_configured(settings: Settings) -> bool:
    """True when a provider has enough configuration to be attempted."""
    return settings.api_key is not None or bool(settings.base_url)
