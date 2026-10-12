"""Report renderers"""

from __future__ import annotations

from skillguard.models import Report
from skillguard.reporters.terminal import render_terminal

__all__ = ["TERMINAL", "render", "render_terminal"]

TERMINAL = "terminal"


def render(report: Report, output_format: str = TERMINAL) -> str | None:

    if output_format == TERMINAL:
        render_terminal(report)
        return None
    raise NotImplementedError(f"output format '{output_format}' is added in Phase 8")
