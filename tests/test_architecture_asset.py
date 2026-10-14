"""Phase 12: the README architecture image is generated from the scene."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCENE = ROOT / "docs" / "architecture.excalidraw"
SVG = ROOT / "docs" / "architecture.svg"
RENDERER = ROOT / "tools" / "render_excalidraw.py"


def _load_renderer() -> Any:
    """Load tools/render_excalidraw.py by path — it is a dev tool, not a package."""
    spec = importlib.util.spec_from_file_location("render_excalidraw", RENDERER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_architecture_svg_matches_the_scene() -> None:
    scene = json.loads(SCENE.read_text(encoding="utf-8"))

    assert _load_renderer().render(scene) == SVG.read_text(encoding="utf-8"), (
        "docs/architecture.svg is stale. Regenerate with:\n"
        "  uv run python tools/render_excalidraw.py "
        "docs/architecture.excalidraw > docs/architecture.svg"
    )


def test_readme_embeds_the_architecture_image() -> None:
    assert "docs/architecture.svg" in (ROOT / "README.md").read_text(encoding="utf-8")
