"""Assemble the final Report"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from skillguard.constants import SCANNER_VERSION
from skillguard.models import Report
from skillguard.state import ScanState


def _skill_name(state: ScanState) -> str:
    """Prefer the name declared in SKILL.md front-matter, else the directory."""
    context = state.get("context")
    if context is None:
        return "unknown"
    declared = context.manifest.get("name")
    if isinstance(declared, str) and declared:
        return declared
    return Path(context.skill_path).name or "unknown"


def report_node(state: ScanState) -> dict[str, object]:
    context = state.get("context")
    risk = state.get("risk")
    if context is None or risk is None:
        return {"errors": ["report: missing context or risk"]}

    return {
        "report": Report(
            skill_name=_skill_name(state),
            source=state.get("input_ref", context.skill_path),
            scanned_at=datetime.now(UTC).isoformat(),
            components=context.components,
            findings=list(state.get("effective_findings", [])),
            risk=risk,
            has_executable_scripts=context.has_executable_scripts,
            llm_requested=bool(state.get("use_llm", False)),
            llm_error=state.get("llm_error"),
            suppressed_findings=list(state.get("suppressed_findings", [])),
            scanner_version=SCANNER_VERSION,
        )
    }
