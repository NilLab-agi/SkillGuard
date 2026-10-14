"""Accepted risk suppression"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from pathlib import Path

from skillguard.models import Finding

# Default baseline file name.
BASELINE_FILENAME = ".skillguardignore"


@dataclass(frozen=True, slots=True)
class BaselineRule:
    """One accepted finding: a rule id plus the paths it is accepted for"""

    rule_id: str
    path_glob: str


@dataclass(frozen=True, slots=True)
class Baseline:
    """The whole baseline file, parsed"""

    rules: tuple[BaselineRule, ...] = ()

    def suppresses(self, finding: Finding) -> bool:
        """True when this finding is already accepted"""
        return any(
            rule.rule_id == finding.rule_id
            and fnmatch.fnmatch(finding.location.file, rule.path_glob)
            for rule in self.rules
        )

    def partition(self, findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
        """Split findings into (kept, suppressed), preserving order"""
        kept: list[Finding] = []
        suppressed: list[Finding] = []
        for finding in findings:
            (suppressed if self.suppresses(finding) else kept).append(finding)
        return kept, suppressed


def parse_baseline(text: str) -> Baseline:
    rules: list[BaselineRule] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        rule_id = parts[0]
        path_glob = parts[1].strip() if len(parts) > 1 else "*"
        rules.append(BaselineRule(rule_id, path_glob))
    return Baseline(tuple(rules))


def load_baseline(path: Path) -> Baseline:
    """Read a baseline file. A missing file is an empty baseline, not an error"""
    if not path.is_file():
        return Baseline()
    return parse_baseline(path.read_text(encoding="utf-8"))


def render_baseline(findings: list[Finding]) -> str:
    """Render a baseline accepting every finding in a scan"""
    lines = [
        "# SkillGuard baseline: accepted findings, excluded from the score.",
        "# Format: <rule_id> <path-glob>",
        "",
    ]
    seen: set[tuple[str, str]] = set()
    for finding in findings:
        key = (finding.rule_id, finding.location.file)
        if key in seen:
            continue
        seen.add(key)
        lines.append(f"{finding.rule_id} {finding.location.file}")
    return "\n".join(lines) + "\n"
