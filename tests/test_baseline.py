"""Phase 12: the baseline file suppresses accepted findings."""

from __future__ import annotations

from pathlib import Path

from skillguard.baseline import (
    BaselineRule,
    load_baseline,
    parse_baseline,
    render_baseline,
)
from skillguard.models import Finding, Location, Severity
from skillguard.nodes.apply_baseline import apply_baseline
from skillguard.pipeline import initial_state, run_scan
from skillguard.state import ScanState

FIXTURES = Path(__file__).parent / "fixtures"


def _finding(rule_id: str, file: str, line: int = 1) -> Finding:
    return Finding(
        rule_id=rule_id,
        category="c",
        severity=Severity.LOW,
        message="m",
        location=Location(file=file, start_line=line),
    )


def _kept(update: dict[str, object]) -> list[Finding]:
    findings = update["effective_findings"]
    assert isinstance(findings, list)
    return findings


def _suppressed(update: dict[str, object]) -> list[Finding]:
    findings = update["suppressed_findings"]
    assert isinstance(findings, list)
    return findings


# ---------------------------------------------------------------- parsing


def test_parse_ignores_comments_and_blanks() -> None:
    baseline = parse_baseline("# a comment\n\nSC1 requirements.txt\n")

    assert baseline.rules == (BaselineRule("SC1", "requirements.txt"),)


def test_a_bare_rule_id_matches_every_path() -> None:
    assert parse_baseline("P1\n").suppresses(_finding("P1", "anything.md"))


def test_glob_matches_paths() -> None:
    baseline = parse_baseline("SC1 requirements*.txt\n")

    assert baseline.suppresses(_finding("SC1", "requirements-dev.txt"))
    assert not baseline.suppresses(_finding("SC1", "pyproject.toml"))


def test_the_rule_id_must_match_too() -> None:
    assert not parse_baseline("SC1 requirements.txt\n").suppresses(
        _finding("SC6", "requirements.txt")
    )


def test_line_numbers_are_not_part_of_the_match() -> None:
    # Otherwise the baseline would churn whenever anyone edits the file.
    assert parse_baseline("P1 SKILL.md\n").suppresses(_finding("P1", "SKILL.md", 99))


def test_missing_baseline_file_is_empty_not_an_error(tmp_path: Path) -> None:
    assert load_baseline(tmp_path / "nope").rules == ()


# ---------------------------------------------------------------- rendering


def test_render_dedupes_rule_file_pairs() -> None:
    findings = [_finding("P1", "SKILL.md", 8), _finding("P1", "SKILL.md", 10)]

    assert render_baseline(findings).count("P1 SKILL.md") == 1


def test_rendered_baseline_round_trips() -> None:
    findings = [_finding("SC1", "requirements.txt"), _finding("P1", "SKILL.md")]

    baseline = parse_baseline(render_baseline(findings))

    assert all(baseline.suppresses(finding) for finding in findings)


# ---------------------------------------------------------------- the node


def test_node_without_a_baseline_passes_through() -> None:
    findings = [_finding("P1", "SKILL.md")]
    update = apply_baseline(ScanState(effective_findings=findings))

    assert _kept(update) == findings
    assert "suppressed_findings" not in update


def test_node_records_what_it_suppressed() -> None:
    state = ScanState(
        effective_findings=[_finding("P1", "SKILL.md"), _finding("SC1", "requirements.txt")],
        baseline=parse_baseline("SC1 requirements.txt\n"),
    )

    update = apply_baseline(state)

    assert [f.rule_id for f in _kept(update)] == ["P1"]
    assert [f.rule_id for f in _suppressed(update)] == ["SC1"]


def test_partition_preserves_order() -> None:
    baseline = parse_baseline("SC1 requirements.txt\n")
    findings = [
        _finding("SC1", "requirements.txt"),
        _finding("P1", "SKILL.md"),
        _finding("SC1", "requirements.txt"),
    ]

    kept, suppressed = baseline.partition(findings)

    assert [f.rule_id for f in kept] == ["P1"]
    assert len(suppressed) == 2


# ------------------------------------------------------- end to end


def test_suppressed_findings_do_not_affect_the_score() -> None:
    """Accepting a risk means accepting it fully, not just hiding it."""
    everything = run_scan(initial_state(str(FIXTURES / "supply_chain_skill")))
    accepted = run_scan(
        initial_state(
            str(FIXTURES / "supply_chain_skill"),
            baseline=parse_baseline(
                "SC1 requirements.txt\nSC6 requirements.txt\nSC10 requirements.txt\n"
            ),
        )
    )

    assert everything["report"].risk.score > accepted["report"].risk.score
    assert accepted["report"].suppressed_findings
    assert "SC1" not in {f.rule_id for f in accepted["report"].findings}
    assert accepted["report"].risk.score == 0


def test_baseline_runs_before_scoring_in_the_graph(tmp_path: Path) -> None:
    from skillguard.pipeline import stream_scan

    skill = tmp_path / "demo-skill"
    skill.mkdir()

    nodes = [name for name, _update in stream_scan(initial_state(str(skill)))]

    assert "apply_baseline" in nodes
    assert nodes.index("deduplicate") < nodes.index("apply_baseline")
    assert nodes.index("apply_baseline") < nodes.index("score")
