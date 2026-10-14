"""Render a small subset of an Excalidraw scene to SVG.

Only the element types ``docs/architecture.excalidraw`` uses: rectangles with
labels, arrows, and standalone text. Keeping the renderer in the repo means the
README image is regenerated from the editable scene, so the two cannot drift.

    uv run python tools/render_excalidraw.py docs/architecture.excalidraw > docs/architecture.svg
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

DEFAULT_CAMERA: dict[str, Any] = {"x": 0, "y": 0, "width": 800, "height": 600}
LINE_HEIGHT = 1.25
CORNER_RADIUS = 12
FONT_STACK = "'Segoe UI', Helvetica, Arial, sans-serif"


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _centered_text(cx: float, cy: float, text: str, size: int, fill: str) -> str:
    """Multi-line text centred on (cx, cy) — used for shape labels."""
    lines = text.split("\n")
    step = size * LINE_HEIGHT
    top = cy - (len(lines) - 1) * step / 2
    return "\n".join(
        f'<text x="{cx:.1f}" y="{top + index * step:.1f}" font-size="{size}" '
        f'text-anchor="middle" dominant-baseline="middle" fill="{fill}">'
        f"{_escape(line)}</text>"
        for index, line in enumerate(lines)
    )


def _rectangle(element: dict[str, Any]) -> str:
    x, y = float(element["x"]), float(element["y"])
    width, height = float(element["width"]), float(element["height"])
    fill = str(element.get("backgroundColor", "transparent"))
    stroke = str(element.get("strokeColor", "#1e1e1e"))
    stroke_width = element.get("strokeWidth", 2)
    opacity = float(element.get("opacity", 100)) / 100
    radius = CORNER_RADIUS if element.get("roundness") else 0

    parts = [
        f'<rect x="{x}" y="{y}" width="{width}" height="{height}" rx="{radius}" '
        f'fill="{fill}" fill-opacity="{opacity}" stroke="{stroke}" '
        f'stroke-width="{stroke_width}" stroke-opacity="{opacity}"/>'
    ]
    label = element.get("label")
    if label:
        parts.append(
            _centered_text(
                x + width / 2,
                y + height / 2,
                str(label["text"]),
                int(label.get("fontSize", 16)),
                "#1e1e1e",
            )
        )
    return "\n".join(parts)


def _arrow(element: dict[str, Any]) -> str:
    x, y = float(element["x"]), float(element["y"])
    points = element.get("points") or [[0, 0], [0, 0]]
    coords = " ".join(f"{x + float(dx):.1f},{y + float(dy):.1f}" for dx, dy in points)
    dashed = ' stroke-dasharray="6 6"' if element.get("strokeStyle") == "dashed" else ""
    head = ' marker-end="url(#head)"' if element.get("endArrowhead", "arrow") else ""
    return (
        f'<polyline points="{coords}" fill="none" '
        f'stroke="{element.get("strokeColor", "#1e1e1e")}" '
        f'stroke-width="{element.get("strokeWidth", 2)}" stroke-linecap="round" '
        f'stroke-linejoin="round"{dashed}{head}/>'
    )


def _standalone_text(element: dict[str, Any]) -> str:
    size = int(element.get("fontSize", 20))
    return (
        f'<text x="{element["x"]}" y="{float(element["y"]) + size:.1f}" '
        f'font-size="{size}" fill="{element.get("strokeColor", "#1e1e1e")}">'
        f"{_escape(str(element.get('text', '')))}</text>"
    )


def render(scene: dict[str, Any]) -> str:
    """Render an Excalidraw scene dict to an SVG document."""
    elements: list[dict[str, Any]] = scene.get("elements", [])
    camera = next((e for e in elements if e.get("type") == "cameraUpdate"), DEFAULT_CAMERA)
    view_box = f"{camera['x']} {camera['y']} {camera['width']} {camera['height']}"

    body: list[str] = []
    for element in elements:
        match element.get("type"):
            case "rectangle":
                body.append(_rectangle(element))
            case "arrow":
                body.append(_arrow(element))
            case "text":
                body.append(_standalone_text(element))
            case _:
                continue

    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="{view_box}" '
        f'width="{camera["width"]}" height="{camera["height"]}" role="img" '
        f'aria-label="SkillGuard architecture: one scan, one LangGraph run">\n'
        "<defs>\n"
        '<marker id="head" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" '
        'markerHeight="6" orient="auto-start-reverse">\n'
        '<path d="M 0 0 L 10 5 L 0 10 z" fill="#1e1e1e"/>\n'
        "</marker>\n"
        f"<style>text {{ font-family: {FONT_STACK}; }}</style>\n"
        "</defs>\n"
        '<rect x="0" y="0" width="100%" height="100%" fill="#ffffff"/>\n'
        + "\n".join(body)
        + "\n</svg>\n"
    )


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    scene = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    sys.stdout.write(render(scene))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
