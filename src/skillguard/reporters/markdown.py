"""Markdown report, for pasting into a PR or an issue"""

from __future__ import annotations

from skillguard.models import Report


def render_markdown(report: Report) -> str:
    """Serialize a report as Markdown"""
    risk = report.risk
    lines = [
        f"# SkillGuard report: {report.skill_name}",
        "",
        f"- **Source:** `{report.source}`",
        f"- **Scanned:** {report.scanned_at}",
        f"- **Scanner:** v{report.scanner_version}",
        f"- **Score:** {risk.score}/100 ({risk.severity.value})",
        f"- **Recommendation:** {risk.recommendation.value}",
        "",
    ]

    if report.components:
        lines += [
            "## Components",
            "",
            "| Path | Type | Lines | Executable |",
            "| --- | --- | --- | --- |",
        ]
        for component in report.components:
            executable = "yes" if component.executable else "no"
            lines.append(
                f"| `{component.path}` | {component.type} | {component.lines} | {executable} |"
            )
        lines.append("")

    lines += [f"## Findings ({len(report.findings)})", ""]
    if not report.findings:
        lines.append("No findings.")
        return "\n".join(lines) + "\n"

    for finding in report.findings:
        lines += [
            f"### {finding.rule_id} — {finding.message}",
            "",
            f"- **Severity:** {finding.severity.value}",
            f"- **Location:** `{finding.location.file}:{finding.location.start_line}`",
            f"- **Confidence:** {finding.confidence:.0%}",
        ]
        if finding.remediation:
            lines.append(f"- **Remediation:** {finding.remediation}")
        if finding.snippet:
            lines += ["", "```", finding.snippet, "```"]
        lines.append("")

    return "\n".join(lines) + "\n"
