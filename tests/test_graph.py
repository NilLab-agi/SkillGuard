"""the graph runs e2e over real fixtures"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from skillguard.graph import build_graph
from skillguard.models import Finding, Location, Severity
from skillguard.pipeline import initial_state, run_scan, stream_scan
from skillguard.state import ScanState

FIXTURES = Path(__file__).parent / "fixtures"


def _finding(rule_id: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        category="test",
        severity=Severity.LOW,
        message="synthetic",
        location=Location(file="SKILL.md", start_line=1),
    )


def _analyzer(rule_id: str) -> Callable[[ScanState], dict[str, object]]:
    def run(state: ScanState) -> dict[str, object]:
        return {"findings": [_finding(rule_id)]}

    return run


def test_malicious_fixture_is_reported_dangerous() -> None:
    final = run_scan(initial_state(str(FIXTURES / "malicious_skill")))
    report = final["report"]

    assert report.skill_name == "malicious-demo"
    assert {f.rule_id for f in report.findings} >= {"P1", "P2", "E1", "E2"}
    assert report.risk.recommendation.value == "DO_NOT_INSTALL"


def test_safe_fixture_is_reported_safe() -> None:
    final = run_scan(initial_state(str(FIXTURES / "safe_skill")))
    report = final["report"]

    assert report.findings == []
    assert report.risk.recommendation.value == "SAFE"


def test_findings_arrive_from_several_parallel_analyzers() -> None:
    final = run_scan(initial_state(str(FIXTURES / "malicious_skill")))
    categories = {f.category for f in final["report"].findings}

    # Three categories can only be present if the reducer merged parallel nodes.
    assert len(categories) >= 3


def test_parallel_analyzers_both_survive_the_merge(tmp_path: Path) -> None:
    skill = tmp_path / "demo-skill"
    skill.mkdir()

    app = build_graph(analyzers={"analyzer_a": _analyzer("A"), "analyzer_b": _analyzer("B")})
    final = app.invoke(initial_state(str(skill)))

    assert sorted(f.rule_id for f in final["findings"]) == ["A", "B"]


def test_stream_emits_each_node_once(tmp_path: Path) -> None:
    skill = tmp_path / "demo-skill"
    skill.mkdir()

    nodes = [name for name, _update in stream_scan(initial_state(str(skill)))]

    assert nodes[0] == "resolve_input"
    assert nodes[-1] == "report"
    assert len(nodes) == len(set(nodes))


# def test_missing_directory_is_recorded_as_an_error(tmp_path: Path) -> None:
#     final = run_scan(initial_state(str(tmp_path / "does-not-exist")))

#     assert any("not a directory" in message for message in final["errors"])


def test_malicious_fixture_includes_ast_findings() -> None:
    final = run_scan(initial_state(str(FIXTURES / "malicious_skill")))
    ids = {f.rule_id for f in final["report"].findings}

    assert {"AST1", "AST8"} <= ids


def test_graph_reports_a_poisoned_mcp_config() -> None:
    final = run_scan(initial_state(str(FIXTURES / "mcp_poisoned_skill")))
    ids = {f.rule_id for f in final["report"].findings}

    assert {"LP2", "TP1"} <= ids


def test_llm_stage_is_skipped_when_not_requested(tmp_path: Path) -> None:
    skill = tmp_path / "demo-skill"
    skill.mkdir()

    nodes = [name for name, _update in stream_scan(initial_state(str(skill), use_llm=False))]

    assert "meta_analyzer" not in nodes
    assert "deduplicate" in nodes


def test_llm_stage_runs_when_requested(tmp_path: Path) -> None:
    skill = tmp_path / "demo-skill"
    skill.mkdir()

    nodes = [name for name, _update in stream_scan(initial_state(str(skill), use_llm=True))]

    assert "meta_analyzer" in nodes
