"""Rich terminal report"""

from __future__ import annotations

from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from skillguard.models import Finding, Report

_console = Console()

_SEVERITY_STYLE: dict[str, str] = {
    "LOW": "green",
    "MEDIUM": "yellow",
    "HIGH": "red",
    "CRITICAL": "bold red",
}

_RECOMMENDATION_STYLE: dict[str, str] = {
    "SAFE": "green",
    "CAUTION": "yellow",
    "DO_NOT_INSTALL": "bold red",
}

# Pygments lexer per component type, so snippets are highlighted correctly
_LEXER_BY_TYPE: dict[str, str] = {
    "python": "python",
    "shell": "bash",
    "javascript": "javascript",
    "typescript": "typescript",
    "json": "json",
    "yaml": "yaml",
    "markdown": "markdown",
}


def _severity_style(severity: str) -> str:
    return _SEVERITY_STYLE.get(severity, "white")


def _title(report: Report) -> Panel:
    return Panel.fit(
        f"[bold]{report.skill_name}[/]\n[dim]{report.source}[/]",
        title=f"SkillGuard v{report.scanner_version}",
        border_style="cyan",
    )


def _summary(report: Report) -> Panel:
    risk = report.risk
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_row("Score", f"[bold]{risk.score}/100[/]")
    table.add_row("Severity", f"[{_severity_style(risk.severity.value)}]{risk.severity.value}[/]")
    recommendation = risk.recommendation.value
    table.add_row(
        "Recommendation",
        f"[{_RECOMMENDATION_STYLE.get(recommendation, 'white')}]{recommendation}[/]",
    )
    return Panel(table, title="Risk assessment", border_style="cyan")


def _components(report: Report) -> Table:
    table = Table(title=f"Components ({len(report.components)})")
    table.add_column("Path")
    table.add_column("Type")
    table.add_column("Lines", justify="right")
    table.add_column("Exec", justify="center")
    for component in report.components:
        table.add_row(
            component.path,
            component.type,
            str(component.lines),
            "[red]yes[/]" if component.executable else "no",
        )
    return table


def _lexer_for(finding: Finding, report: Report) -> str:
    for component in report.components:
        if component.path == finding.location.file:
            return _LEXER_BY_TYPE.get(component.type, "text")
    return "text"


def _finding_panel(finding: Finding, report: Report, index: int) -> Panel:
    style = _severity_style(finding.severity.value)
    header = Text.assemble(
        (f"#{index} ", "dim"),
        (f"{finding.rule_id} ", "bold"),
        (finding.severity.value, style),
        ("  ", ""),
        (f"{finding.location.file}:{finding.location.start_line}", "dim"),
    )

    body = Text()
    body.append(f"{finding.message}\n", style="bold")
    if finding.remediation:
        body.append(f"remediation: {finding.remediation}\n", style="dim")
    body.append(f"confidence: {finding.confidence:.0%}", style="dim")

    parts: list[RenderableType] = [body]
    if finding.snippet:
        parts.append(Syntax(finding.snippet, _lexer_for(finding, report), word_wrap=True))

    return Panel(Group(*parts), title=header, border_style=style, expand=False)


def render_terminal(report: Report, *, console: Console | None = None) -> None:
    """Print the full terminal report"""
    out = console if console is not None else _console
    out.print(_title(report))
    out.print(_summary(report))

    if report.components:
        out.print(_components(report))

    if report.findings:
        out.print(f"\n[bold]Findings ({len(report.findings)})[/]")
        for index, finding in enumerate(report.findings, start=1):
            out.print(_finding_panel(finding, report, index))
    else:
        out.print("[green]No findings.[/]")

    if report.suppressed_findings:
        out.print(f"\n[dim]Suppressed by baseline ({len(report.suppressed_findings)})[/]")
        for finding in report.suppressed_findings:
            out.print(
                f"[dim]  {finding.rule_id}  "
                f"{finding.location.file}:{finding.location.start_line}  "
                f"{finding.message}[/]"
            )
