"""Score node: turn the deduplicated findings into a RiskAssessment"""

from __future__ import annotations

from skillguard.scoring import score_findings
from skillguard.state import ScanState


def score_node(state: ScanState) -> dict[str, object]:
    context = state.get("context")
    has_executable_scripts = bool(context.has_executable_scripts) if context else False
    return {
        "risk": score_findings(
            list(state.get("effective_findings", [])),
            has_executable_scripts=has_executable_scripts,
        )
    }
