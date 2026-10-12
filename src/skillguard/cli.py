"""SkillGuard command line interface"""

from __future__ import annotations

from enum import StrEnum

import typer
from rich.console import Console
from rich.panel import Panel

from skillguard import __version__
from skillguard.models import Report
from skillguard.pipeline import initial_state, stream_scan
from skillguard.reporters import render

app = typer.Typer(
    name="skillguard",
    help="Static security scanner for AI agent skills",
    no_args_is_help=True,
)
console = Console()


class OutputFormat(StrEnum):
    """Report formats supported by the CLI"""

    terminal = "terminal"
    json = "json"
    markdown = "markdown"
    sarif = "sarif"


def _version_callback(value: bool) -> None:
    if value:
        console.print(Panel.fit(f"SkillGuard [bold cyan]v{__version__}[/]", border_style="cyan"))
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        False,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show the SkillGuard version and exit.",
    ),
) -> None:
    """SkillGuard: scan untrusted agent skills before you install them"""


@app.command()
def scan(
    path: str = typer.Argument(..., help="Skill directory to scan"),
    output_format: OutputFormat = typer.Option(
        OutputFormat.terminal, "--format", "-f", help="Report format."
    ),
    no_llm: bool = typer.Option(False, "--no-llm", help="Static analysis only"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Print each node as it runs"),
) -> None:
    """Scan a skill directory and print a risk report"""
    state = initial_state(
        path,
        output_format=output_format.value,
        use_llm=not no_llm,
        verbose=verbose,
    )

    report: Report | None = None
    for node_name, update in stream_scan(state):
        if verbose:
            console.print(f"[green]OK[/] {node_name}")
        candidate = update.get("report")
        if isinstance(candidate, Report):
            report = candidate

    if report is None:
        console.print("[red]Scan failed: no report produced[/]")
        raise typer.Exit(code=2)

    try:
        render(report, output_format.value)
    except NotImplementedError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(code=2) from exc


if __name__ == "__main__":
    app()
