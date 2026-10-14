"""settings come from the environment, and secrets stay secret."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from skillguard.config import Settings

PREFIXED = (
    "SKILLGUARD_PROVIDER",
    "SKILLGUARD_MODEL",
    "SKILLGUARD_MAX_FILES",
    "SKILLGUARD_LOG_LEVEL",
    "SKILLGUARD_API_KEY",
)


@pytest.fixture
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove prefixed variables so defaults are deterministic."""
    for name in PREFIXED:
        monkeypatch.delenv(name, raising=False)


def test_defaults_are_used_when_nothing_is_set(clean_env: None) -> None:
    settings = Settings()
    # These are the project defaults; pin them so a silent change is caught.
    assert settings.provider == "deepseek"
    assert settings.model == "deepseek-flash"
    assert settings.max_files > 0


def test_prefixed_env_is_read(clean_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SKILLGUARD_PROVIDER", "ollama")
    monkeypatch.setenv("SKILLGUARD_MAX_FILES", "42")
    settings = Settings()
    assert settings.provider == "ollama"
    assert settings.max_files == 42


def test_invalid_log_level_is_rejected(clean_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SKILLGUARD_LOG_LEVEL", "LOUD")
    with pytest.raises(ValidationError):
        Settings()


def test_blank_api_key_means_not_configured(
    clean_env: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SKILLGUARD_API_KEY", "")
    assert Settings().api_key is None


def test_api_key_never_appears_in_output(clean_env: None, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SKILLGUARD_API_KEY", "sk-super-secret")
    settings = Settings()
    assert settings.api_key is not None
    assert settings.api_key.get_secret_value() == "sk-super-secret"
    assert "sk-super-secret" not in settings.model_dump_json()
    assert "sk-super-secret" not in repr(settings)
