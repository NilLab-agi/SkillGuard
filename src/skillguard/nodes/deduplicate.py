"""Collapse duplicate findings and order them for a stable report"""

from __future__ import annotations

from skillguard.models import Finding
from skillguard.state import ScanState


def deduplicate(state: ScanState) -> dict[str, object]:
    """Deduplicate by (rule, file, line) and sort by location"""
    unique: dict[tuple[str, str, int], Finding] = {}
    for finding in state.get("findings", []):
        key = (finding.rule_id, finding.location.file, finding.location.start_line)
        unique.setdefault(key, finding)

    ordered = sorted(
        unique.values(),
        key=lambda finding: (
            finding.location.file,
            finding.location.start_line,
            finding.rule_id,
        ),
    )
    return {"effective_findings": ordered}
