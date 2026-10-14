"""Choose a reviewer from settings."""

from __future__ import annotations

from skillguard.config import Settings
from skillguard.providers.base import Reviewer
from skillguard.providers.openai_compat import OpenAICompatReviewer


def build_reviewer(settings: Settings) -> Reviewer:
    """Build the reviewer for the configured provider.

    Only one provider exists by design: it drives OpenAI, Ollama, vLLM,
    OpenRouter and most gateways through ``base_url``.
    """
    return OpenAICompatReviewer(settings)


def is_configured(settings: Settings) -> bool:
    """True when a provider has enough configuration to be attempted."""
    return settings.api_key is not None or bool(settings.base_url)
