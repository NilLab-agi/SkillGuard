"""severity points, the executable multiplier, and band boundaries."""

from __future__ import annotations

import pytest

from skillguard.models import Finding, Location, Severity
from skillguard.scoring import EXECUTABLE_MULTIPLIER, band, score_findings


def _finding(severity: Severity) -> Finding:
    return Finding(
        rule_id="X",
        category="test",
        severity=severity,
        message="synthetic",
        location=Location(file="SKILL.md", start_line=1),
    )


@pytest.mark.parametrize(
    ("score", "severity", "recommendation"),
    [
        (0, "LOW", "SAFE"),
        (20, "LOW", "SAFE"),
        (21, "MEDIUM", "CAUTION"),
        (50, "MEDIUM", "CAUTION"),
        (51, "HIGH", "DO_NOT_INSTALL"),
        (80, "HIGH", "DO_NOT_INSTALL"),
        (81, "CRITICAL", "DO_NOT_INSTALL"),
        (100, "CRITICAL", "DO_NOT_INSTALL"),
    ],
)
def test_band_boundaries(score: int, severity: str, recommendation: str) -> None:
    got_severity, got_recommendation = band(score)

    assert (got_severity.value, got_recommendation.value) == (severity, recommendation)


def test_no_findings_scores_zero_and_safe() -> None:
    risk = score_findings([], has_executable_scripts=True)

    assert risk.score == 0
    assert risk.recommendation.value == "SAFE"


def test_points_sum_without_executable_scripts() -> None:
    findings = [_finding(Severity.HIGH), _finding(Severity.MEDIUM)]

    assert score_findings(findings, has_executable_scripts=False).score == 35


def test_multiplier_applies_with_executable_scripts() -> None:
    findings = [_finding(Severity.HIGH)]

    score = score_findings(findings, has_executable_scripts=True).score

    assert score == int(25 * EXECUTABLE_MULTIPLIER)


def test_score_is_clamped_to_100() -> None:
    findings = [_finding(Severity.CRITICAL) for _ in range(5)]

    assert score_findings(findings, has_executable_scripts=True).score == 100


def test_one_critical_with_scripts_reaches_do_not_install() -> None:
    # Part 3.3 rationale: the most severe finding must be able to block.
    risk = score_findings([_finding(Severity.CRITICAL)], has_executable_scripts=True)

    assert risk.score == 65
    assert risk.severity.value == "HIGH"
    assert risk.recommendation.value == "DO_NOT_INSTALL"


def test_one_critical_without_scripts_is_only_caution() -> None:
    risk = score_findings([_finding(Severity.CRITICAL)], has_executable_scripts=False)

    assert risk.score == 50
    assert risk.recommendation.value == "CAUTION"
