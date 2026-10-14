"""Drop findings the user has explicitly accepted, before scoring"""

from __future__ import annotations

from skillguard.state import ScanState


def apply_baseline(state: ScanState) -> dict[str, object]:
    """Split effective findings into kept and suppressed"""
    findings = list(state.get("effective_findings", []))
    baseline = state.get("baseline")
    if baseline is None:
        return {"effective_findings": findings}

    kept, suppressed = baseline.partition(findings)
    return {"effective_findings": kept, "suppressed_findings": suppressed}
