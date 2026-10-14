"""the machine readable contracts JSON, Markdown and SARIF"""

from __future__ import annotations

import json

from skillguard.constants import SCANNER_VERSION
from skillguard.models import (
    Component,
    Finding,
    Location,
    Recommendation,
    Report,
    RiskAssessment,
    Severity,
)
from skillguard.reporters.json_report import render_json, to_wire
from skillguard.reporters.markdown import render_markdown
from skillguard.reporters.sarif import render_sarif, to_sarif


def _fixed_report() -> Report:
    """A report with no clock and no filesystem: safe to snapshot"""
    return Report(
        skill_name="demo-skill",
        source="./demo-skill",
        scanned_at="2026-01-29T10:30:00Z",
        components=[
            Component(path="SKILL.md", type="markdown", lines=10),
            Component(path="scripts/exfil.py", type="python", lines=11, executable=True),
        ],
        findings=[
            Finding(
                rule_id="P1",
                category="prompt_injection",
                severity=Severity.HIGH,
                message="Instruction override attempt",
                location=Location(file="SKILL.md", start_line=8),
                snippet="Ignore all previous instructions.",
                remediation="Remove the overriding instruction.",
                confidence=0.85,
            )
        ],
        risk=RiskAssessment(
            score=78,
            severity=Severity.HIGH,
            recommendation=Recommendation.DO_NOT_INSTALL,
        ),
        has_executable_scripts=True,
        llm_requested=False,
    )


# ---------------------------------------------------------------- JSON contract


def test_json_top_level_shape() -> None:
    wire = to_wire(_fixed_report())

    assert list(wire) == ["skill", "risk_assessment", "components", "issues", "metadata"]


def test_json_uses_the_published_names() -> None:
    wire = to_wire(_fixed_report())
    issue = wire["issues"][0]

    assert issue["id"] == "P1"  # internal rule_id -> published "id"
    assert issue["severity"] == "HIGH"  # enum serialized as its value
    assert issue["location"] == {"file": "SKILL.md", "start_line": 8}
    assert wire["skill"]["name"] == "demo-skill"


def test_json_metadata_is_present() -> None:
    wire = to_wire(_fixed_report())

    assert wire["metadata"] == {
        "has_executable_scripts": True,
        "scanner_version": SCANNER_VERSION,
        "llm_requested": False,
        "suppressed": 0,
    }


def test_json_is_valid_and_parseable() -> None:
    parsed = json.loads(render_json(_fixed_report()))

    assert parsed["risk_assessment"]["recommendation"] == "DO_NOT_INSTALL"
    assert len(parsed["issues"]) == 1


def test_json_contract_snapshot(snapshot: object) -> None:
    # A snapshot is the right tool for a *contract*: any key rename fails here.
    assert render_json(_fixed_report()) == snapshot


# --------------------------------------------------------------- SARIF contract


def test_sarif_header_and_driver() -> None:
    sarif = to_sarif(_fixed_report())
    driver = sarif["runs"][0]["tool"]["driver"]

    assert sarif["$schema"].endswith("sarif-2.1.0.json")
    assert sarif["version"] == "2.1.0"
    assert driver["name"] == "SkillGuard"
    assert driver["version"] == SCANNER_VERSION


def test_sarif_rule_catalogue_is_deduplicated() -> None:
    report = _fixed_report()
    report = report.model_copy(update={"findings": [report.findings[0], report.findings[0]]})
    rules = to_sarif(report)["runs"][0]["tool"]["driver"]["rules"]

    assert [rule["id"] for rule in rules] == ["P1"]


def test_sarif_result_points_at_the_line() -> None:
    result = to_sarif(_fixed_report())["runs"][0]["results"][0]
    location = result["locations"][0]["physicalLocation"]

    assert result["ruleId"] == "P1"
    assert location["artifactLocation"]["uri"] == "SKILL.md"
    assert location["region"]["startLine"] == 8


def test_sarif_levels_follow_severity() -> None:
    levels = {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }
    for severity, expected in levels.items():
        finding = _fixed_report().findings[0].model_copy(update={"severity": Severity(severity)})
        report = _fixed_report().model_copy(update={"findings": [finding]})
        assert to_sarif(report)["runs"][0]["results"][0]["level"] == expected


def test_sarif_is_valid_json() -> None:
    assert json.loads(render_sarif(_fixed_report()))["version"] == "2.1.0"


# -------------------------------------------------------------- Markdown output


def test_markdown_reports_the_decision() -> None:
    text = render_markdown(_fixed_report())

    assert "# SkillGuard report: demo-skill" in text
    assert "78/100" in text
    assert "DO_NOT_INSTALL" in text
    assert "### P1 — Instruction override attempt" in text


def test_markdown_lists_components() -> None:
    text = render_markdown(_fixed_report())

    assert "| `scripts/exfil.py` | python | 11 | yes |" in text


def test_markdown_says_no_findings_when_clean() -> None:
    report = _fixed_report().model_copy(update={"findings": []})
    text = render_markdown(report)

    assert "No findings." in text
