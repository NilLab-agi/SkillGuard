"""SkillGuard command-line interface"""

from __future__ import annotations

import shutil
from enum import StrEnum
from pathlib import Path

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

# Exit code 1 is also raised when a strict gate (--fail-on-findings) fires
BLOCK_THRESHOLD = 50


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


def _exit_code(report: Report, *, fail_on_findings: bool) -> int:
    """0 = clean or caution, 1 = blocked. Errors exit 2 before this is reached"""
    if fail_on_findings and report.findings:
        return 1
    return 1 if report.risk.score > BLOCK_THRESHOLD else 0


@app.command()
def scan(
    path: str = typer.Argument(..., help="Skill directory to scan."),
    output_format: OutputFormat = typer.Option(
        OutputFormat.terminal, "--format", "-f", help="Report format."
    ),
    output: str | None = typer.Option(
        None, "--output", "-o", help="Write the report to this file instead of stdout."
    ),
    no_llm: bool = typer.Option(False, "--no-llm", help="Static analysis only."),
    osv: bool = typer.Option(
        False, "--osv", help="Look up known vulnerabilities on osv.dev (network egress)."
    ),
    fail_on_findings: bool = typer.Option(
        False, "--fail-on-findings", help="Exit 1 if any finding is present."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Print each node as it runs."),
) -> None:
    """Scan a skill directory and print a risk report"""
    state = initial_state(
        path,
        output_format=output_format.value,
        use_llm=not no_llm,
        use_osv=osv,
        verbose=verbose,
    )

    report: Report | None = None
    errors: list[str] = []
    cleanup_dir: str | None = None

    try:
        for node_name, update in stream_scan(state):
            if verbose:
                console.print(f"[green]OK[/] {node_name}")
            candidate = update.get("report")
            if isinstance(candidate, Report):
                report = candidate
            node_errors = update.get("errors")
            if isinstance(node_errors, list):
                errors.extend(str(message) for message in node_errors)
            node_cleanup = update.get("cleanup_dir")
            if isinstance(node_cleanup, str) and node_cleanup:
                cleanup_dir = node_cleanup

        # Fail closed: an input error must never look like a clean scan.
        if errors:
            for message in errors:
                console.print(f"[red]error:[/] {message}")
            raise typer.Exit(code=2)

        if report is None:
            console.print("[red]Scan failed: no report produced.[/]")
            raise typer.Exit(code=2)

        rendered = render(report, output_format.value)
        if rendered is not None:
            if output:
                Path(output).write_text(rendered, encoding="utf-8")
            else:
                # typer.echo, not console.print: JSON must not be read as Rich markup.
                typer.echo(rendered)

        raise typer.Exit(code=_exit_code(report, fail_on_findings=fail_on_findings))
    finally:
        # Zip/git inputs live in a temp dir; remove it even on error or Ctrl-C.
        if cleanup_dir:
            shutil.rmtree(cleanup_dir, ignore_errors=True)

    # report: Report | None = None
    # errors: list[str] = []
    # cleanup_dir: str | None = None

    # try:
    #     for node_name, update in stream_scan(state):
    #         if verbose:
    #             console.print(f"[green]OK[/] {node_name}")
    #         candidate = update.get("report")
    #         if isinstance(candidate, Report):
    #             report = candidate
    #         node_errors = update.get("errors")
    #         if isinstance(node_errors, list):
    #             errors.extend(str(message) for message in node_errors)
    #         node_cleanup = update.get("cleanup_dir")
    #         if isinstance(node_cleanup, str) and node_cleanup:
    #             cleanup_dir = node_cleanup

    #     # Fail closed: an input error must never look like a clean scan
    #     if errors:
    #         for message in errors:
    #             console.print(f"[red]error:[/] {message}")
    #         raise typer.Exit(code=2)

    #     if report is None:
    #         console.print("[red]Scan failed: no report produced.[/]")
    #         raise typer.Exit(code=2)

    #     rendered = render(report, output_format.value)
    #     if rendered is not None:
    #         if output:
    #             Path(output).write_text(rendered, encoding="utf-8")
    #         else:
    #             # typer.echo, not console.print: JSON must not be read as Rich markup.
    #             typer.echo(rendered)

    #     raise typer.Exit(code=_exit_code(report, fail_on_findings=fail_on_findings))
    # finally:
    #     # Zip/git inputs live in a temp dir; remove it even on error or Ctrl-C
    #     if cleanup_dir:
    #         shutil.rmtree(cleanup_dir, ignore_errors=True)

    # -------

    # report: Report | None = None
    # errors: list[str] = []
    # for node_name, update in stream_scan(state):
    #     if verbose:
    #         console.print(f"[green]OK[/] {node_name}")
    #     candidate = update.get("report")
    #     if isinstance(candidate, Report):
    #         report = candidate
    #     node_errors = update.get("errors")
    #     if isinstance(node_errors, list):
    #         errors.extend(str(message) for message in node_errors)

    # # Fail closed: an input error must never look like a clean scan.
    # if errors:
    #     for message in errors:
    #         console.print(f"[red]error:[/] {message}")
    #     raise typer.Exit(code=2)

    # if report is None:
    #     console.print("[red]Scan failed: no report produced.[/]")
    #     raise typer.Exit(code=2)

    # rendered = render(report, output_format.value)
    # if rendered is not None:
    #     if output:
    #         Path(output).write_text(rendered, encoding="utf-8")
    #     else:
    #         # typer.echo, not console.print: JSON must not be read as Rich markup.
    #         typer.echo(rendered)

    # raise typer.Exit(code=_exit_code(report, fail_on_findings=fail_on_findings))


if __name__ == "__main__":
    app()
