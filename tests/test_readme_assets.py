"""Every image the README embeds from docs/ exists on disk."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
IMAGE_REF = re.compile(r"!\[[^\]]*\]\((docs/[^)]+)\)")


def test_readme_images_exist() -> None:
    refs = IMAGE_REF.findall(README.read_text(encoding="utf-8"))
    assert "docs/architecture.png" in refs, "the architecture image is no longer embedded"
    missing = [ref for ref in refs if not (ROOT / ref).is_file()]
    assert not missing, f"README references missing images: {missing}"
