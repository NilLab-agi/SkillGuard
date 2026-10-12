"""LLM semantic review of findings"""

from __future__ import annotations

from skillguard.state import ScanState


def meta_analyzer(state: ScanState) -> dict[str, object]:
    return {"effective_findings": list(state.get("effective_findings", []))}
