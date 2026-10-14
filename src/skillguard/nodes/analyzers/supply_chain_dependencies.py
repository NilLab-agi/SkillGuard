"""Dependency rules: SC1 unpinned, SC6 typosquat, SC10 source redirection."""

from __future__ import annotations

from skillguard.dependencies import Dependency, DependencySource, collect_dependencies, typosquat_of
from skillguard.models import Finding, Location, Severity
from skillguard.state import ScanState

_CATEGORY = "supply_chain"


def _finding(
    rule_id: str,
    severity: Severity,
    message: str,
    remediation: str,
    confidence: float,
    source: str,
    line: int,
    snippet: str = "",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=_CATEGORY,
        severity=severity,
        message=message,
        location=Location(file=source, start_line=line),
        snippet=snippet,
        confidence=confidence,
        remediation=remediation,
    )


def _unpinned(dependency: Dependency) -> Finding:
    return _finding(
        "SC1",
        Severity.LOW,
        f"Dependency '{dependency.name}' has no version constraint",
        "Pin the dependency to an exact version for reproducible installs.",
        0.85,
        dependency.source,
        dependency.line,
        dependency.name,
    )


def _typosquat(dependency: Dependency, popular: str) -> Finding:
    return _finding(
        "SC6",
        Severity.HIGH,
        f"Dependency '{dependency.name}' looks like '{popular}' (possible typosquat)",
        f"Check the spelling; if you meant '{popular}', fix the name.",
        0.7,
        dependency.source,
        dependency.line,
        dependency.name,
    )


def _redirect(entry: DependencySource) -> Finding:
    return _finding(
        "SC10",
        Severity.HIGH,
        f"Dependency source redirected ({entry.reason})",
        "Install from the default package index unless you control the source.",
        0.8,
        entry.source,
        entry.line,
        entry.target,
    )


def supply_chain_dependencies(state: ScanState) -> dict[str, object]:
    """Analyzer node: dependency declarations and where they come from."""
    context = state.get("context")
    if context is None:
        return {"findings": []}

    report = collect_dependencies(context)
    findings: list[Finding] = []

    for dependency in report.dependencies:
        if not dependency.specifier:
            findings.append(_unpinned(dependency))
        popular = typosquat_of(dependency.name)
        if popular is not None:
            findings.append(_typosquat(dependency, popular))

    findings.extend(_redirect(entry) for entry in report.redirects)
    return {"findings": findings}
