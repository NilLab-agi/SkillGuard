"""Only the subset CI and IDEs consume: one run, the tool driver with its rule
catalogue, and one result per finding"""

from __future__ import annotations

import json
from typing import Any

from skillguard.models import Finding, Report

_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_VERSION = "2.1.0"
_INFORMATION_URI = "https://github.com/NilLab-agi/SkillGuard"

#: SARIF levels are error | warning | note.
_LEVEL_BY_SEVERITY: dict[str, str] = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

#: GitHub code scanning ranks alerts by this 0-10 score.
_SECURITY_SEVERITY: dict[str, str] = {
    "CRITICAL": "9.5",
    "HIGH": "8.0",
    "MEDIUM": "5.0",
    "LOW": "2.0",
}


def _rule_catalogue(findings: list[Finding]) -> list[dict[str, Any]]:
    catalogue: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if finding.rule_id in catalogue:
            continue
        catalogue[finding.rule_id] = {
            "id": finding.rule_id,
            "name": finding.rule_id,
            "shortDescription": {"text": finding.message},
            "help": {"text": finding.remediation or finding.message},
            "properties": {
                "category": finding.category,
                "security-severity": _SECURITY_SEVERITY.get(finding.severity.value, "0.0"),
            },
        }
    return list(catalogue.values())


def _result(finding: Finding) -> dict[str, Any]:
    return {
        "ruleId": finding.rule_id,
        "level": _LEVEL_BY_SEVERITY.get(finding.severity.value, "warning"),
        "message": {"text": finding.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.location.file},
                    "region": {"startLine": finding.location.start_line},
                }
            }
        ],
        "properties": {"confidence": finding.confidence},
    }


def to_sarif(report: Report) -> dict[str, Any]:
    """Build the SARIF document for a report."""
    return {
        "$schema": _SCHEMA,
        "version": _VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SkillGuard",
                        "version": report.scanner_version,
                        "informationUri": _INFORMATION_URI,
                        "rules": _rule_catalogue(report.findings),
                    }
                },
                "results": [_result(finding) for finding in report.findings],
            }
        ],
    }


def render_sarif(report: Report) -> str:
    """Serialize a report as SARIF 2.1.0."""
    return json.dumps(to_sarif(report), indent=2)
