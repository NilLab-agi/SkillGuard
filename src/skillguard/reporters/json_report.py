from __future__ import annotations

import json
from typing import Any

from skillguard.models import Report


def to_wire(report: Report) -> dict[str, Any]:
    """Map the internal Report onto the published JSON shape"""
    return {
        "skill": {
            "name": report.skill_name,
            "source": report.source,
            "scanned_at": report.scanned_at,
        },
        "risk_assessment": report.risk.model_dump(mode="json"),
        "components": [component.model_dump(mode="json") for component in report.components],
        "issues": [
            {
                "id": finding.rule_id,
                "category": finding.category,
                "severity": finding.severity.value,
                "confidence": finding.confidence,
                "message": finding.message,
                "location": {
                    "file": finding.location.file,
                    "start_line": finding.location.start_line,
                },
                "snippet": finding.snippet,
                "remediation": finding.remediation,
                "llm_outcome": finding.llm_outcome,
            }
            for finding in report.findings
        ],
        "metadata": {
            "has_executable_scripts": report.has_executable_scripts,
            "scanner_version": report.scanner_version,
            "llm_requested": report.llm_requested,
        },
    }


def render_json(report: Report) -> str:
    """Serialize a report to the published JSON contract"""
    return json.dumps(to_wire(report), indent=2)
