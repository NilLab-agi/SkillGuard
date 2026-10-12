"""Report renderers"""

from __future__ import annotations

from skillguard.models import Report
from skillguard.reporters.json_report import render_json
from skillguard.reporters.markdown import render_markdown
from skillguard.reporters.sarif import render_sarif
from skillguard.reporters.terminal import render_terminal

__all__ = ["FORMATS", "render"]

# Output formats the CLI can produce
FORMATS: frozenset[str] = frozenset({"terminal", "json", "markdown", "sarif"})


def render(report: Report, output_format: str = "terminal") -> str | None:
    """Render ``report`` in ``output_format``."""
    if output_format == "terminal":
        render_terminal(report)
        return None
    if output_format == "json":
        return render_json(report)
    if output_format == "markdown":
        return render_markdown(report)
    if output_format == "sarif":
        return render_sarif(report)
    raise ValueError(f"unknown output format: {output_format!r}")
