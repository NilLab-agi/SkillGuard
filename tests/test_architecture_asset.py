"""The README architecture image exists and is embedded."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGE = ROOT / "docs" / "architecture.png"


def test_readme_embeds_the_architecture_image() -> None:
    assert IMAGE.is_file(), "docs/architecture.png is missing"
    assert "docs/architecture.png" in (ROOT / "README.md").read_text(encoding="utf-8")
