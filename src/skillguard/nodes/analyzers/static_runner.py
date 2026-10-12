"""Apply static rules to a ScanContext and produce Findings"""

from __future__ import annotations

from skillguard.models import Finding, Location, ScanContext
from skillguard.nodes.analyzers.common import iter_eligible_files, line_of, snippet_for
from skillguard.nodes.analyzers.pattern_defaults import rules_for


def run_rules(context: ScanContext, category: str) -> list[Finding]:
    """Run every rule in ``category`` over the context's cached files"""
    findings: list[Finding] = []

    for rule in rules_for(category):
        # One finding per rule per file per LINE. A line matching twice (or a
        # pattern with overlapping matches) would otherwise inflate the score
        seen_lines: set[tuple[str, int]] = set()

        for path, text in iter_eligible_files(context, rule.file_types):
            for match in rule.pattern.finditer(text):
                line = line_of(text, match.start())
                if (path, line) in seen_lines:
                    continue
                seen_lines.add((path, line))

                findings.append(
                    Finding(
                        rule_id=rule.id,
                        category=rule.category,
                        severity=rule.severity,
                        message=rule.message,
                        location=Location(file=path, start_line=line),
                        snippet=snippet_for(text, match),
                        confidence=rule.confidence,
                        remediation=rule.remediation,
                    )
                )

    return findings
