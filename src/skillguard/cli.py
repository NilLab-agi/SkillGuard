"""SkillGuard command-line interface"""

from __future__ import annotations

import shutil
from enum import StrEnum
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel

from skillguard import __version__
from skillguard.baseline import (
    BASELINE_FILENAME,
    Baseline,
    load_baseline,
    render_baseline,
)
from skillguard.models import Report
from skillguard.pipeline import initial_state, stream_scan
from skillguard.reporters import render

app = typer.Typer(
    name="skillguard",
    help="Static security scanner for AI agent skills.",
    no_args_is_help=True,
)
console = Console()

#: Scores above this block the scan (exit 1), per Part 3.4.
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
    """SkillGuard: scan untrusted agent skills before you install them."""


def _exit_code(report: Report, *, fail_on_findings: bool) -> int:
    """0 = clean or caution, 1 = blocked. Errors exit 2 before this is reached."""
    if fail_on_findings and report.findings:
        return 1
    return 1 if report.risk.score > BLOCK_THRESHOLD else 0


def _execute(
    path: str,
    *,
    output_format: str = "terminal",
    use_llm: bool,
    use_osv: bool,
    verbose: bool,
    baseline: Baseline | None,
) -> tuple[Report | None, list[str], str | None]:
    """Run the graph. Returns (report, node errors, temp dir to clean up).

    Cleanup is the caller's job: only it knows when the scan is really over.
    """
    state = initial_state(
        path,
        output_format=output_format,
        use_llm=use_llm,
        use_osv=use_osv,
        verbose=verbose,
        baseline=baseline,
    )

    report: Report | None = None
    errors: list[str] = []
    cleanup_dir: str | None = None

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

    return report, errors, cleanup_dir


def _fail(errors: list[str], report: Report | None) -> None:
    """Fail closed: an input error must never look like a clean scan."""
    if errors:
        for message in errors:
            console.print(f"[red]error:[/] {message}")
        raise typer.Exit(code=2)
    if report is None:
        console.print("[red]Scan failed: no report produced.[/]")
        raise typer.Exit(code=2)


@app.command()
def scan(
    path: str = typer.Argument(..., help="Skill directory, .md file, .zip or git URL."),
    output_format: OutputFormat = typer.Option(
        OutputFormat.terminal, "--format", "-f", help="Report format."
    ),
    output: str | None = typer.Option(
        None, "--output", "-o", help="Write the report to this file instead of stdout."
    ),
    baseline_path: str | None = typer.Option(
        None,
        "--baseline",
        help=f"Suppress findings accepted in this file (e.g. {BASELINE_FILENAME}).",
    ),
    llm: bool = typer.Option(
        False,
        "--llm/--no-llm",
        help="Review findings with a model. Sends file contents off-machine.",
    ),
    osv: bool = typer.Option(
        False, "--osv", help="Look up known vulnerabilities on osv.dev (network egress)."
    ),
    fail_on_findings: bool = typer.Option(
        False, "--fail-on-findings", help="Exit 1 if any finding is present."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Print each node as it runs."),
) -> None:
    """Scan a skill and print a risk report."""
    baseline = load_baseline(Path(baseline_path)) if baseline_path else None
    report, errors, cleanup_dir = _execute(
        path,
        output_format=output_format.value,
        use_llm=llm,
        use_osv=osv,
        verbose=verbose,
        baseline=baseline,
    )

    try:
        _fail(errors, report)
        assert report is not None  # _fail guarantees this

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


@app.command("baseline")
def baseline_command(
    path: str = typer.Argument(..., help="Skill to accept the current findings for."),
    output: str = typer.Option(
        BASELINE_FILENAME, "--output", "-o", help="Where to write the baseline."
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Print each node as it runs."),
) -> None:
    """Accept every current finding, so later scans report only new ones."""
    report, errors, cleanup_dir = _execute(
        path,
        use_llm=False,
        use_osv=False,
        verbose=verbose,
        baseline=None,
    )

    try:
        _fail(errors, report)
        assert report is not None

        Path(output).write_text(render_baseline(report.findings), encoding="utf-8")
        console.print(
            f"[green]wrote[/] {output} with {len(report.findings)} accepted "
            f"finding(s) from [bold]{report.skill_name}[/]"
        )
    finally:
        if cleanup_dir:
            shutil.rmtree(cleanup_dir, ignore_errors=True)


if __name__ == "__main__":
    app()
