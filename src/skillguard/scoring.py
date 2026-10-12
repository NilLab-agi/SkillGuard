"""Risk scoring"""

from __future__ import annotations

from collections.abc import Iterable

from skillguard.models import (
    SEVERITY_POINTS,
    Finding,
    Recommendation,
    RiskAssessment,
    Severity,
)

# Research (SkillSpector): skills with executable scripts are far more likely
# to be vulnerable, so their findings weigh a little more
EXECUTABLE_MULTIPLIER = 1.3

# (inclusive upper score bound, severity, recommendation)
BANDS: tuple[tuple[int, Severity, Recommendation], ...] = (
    (20, Severity.LOW, Recommendation.SAFE),
    (50, Severity.MEDIUM, Recommendation.CAUTION),
    (80, Severity.HIGH, Recommendation.DO_NOT_INSTALL),
    (100, Severity.CRITICAL, Recommendation.DO_NOT_INSTALL),
)


def band(score: int) -> tuple[Severity, Recommendation]:
    """Map a 0-100 score onto its severity band and recommendation"""
    for upper, severity, recommendation in BANDS:
        if score <= upper:
            return severity, recommendation
    return Severity.CRITICAL, Recommendation.DO_NOT_INSTALL


def score_findings(findings: Iterable[Finding], *, has_executable_scripts: bool) -> RiskAssessment:
    """Score a set of findings. The only place scores are produced"""
    total = sum(SEVERITY_POINTS[finding.severity] for finding in findings)
    if has_executable_scripts:
        total = int(total * EXECUTABLE_MULTIPLIER)
    total = min(total, 100)
    severity, recommendation = band(total)
    return RiskAssessment(score=total, severity=severity, recommendation=recommendation)
