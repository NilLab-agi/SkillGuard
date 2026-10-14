"""CLI formats, output files, and exit codes"""

from __future__ import annotations

import json
import tempfile
import zipfile
from pathlib import Path

from typer.testing import CliRunner

from skillguard.cli import OutputFormat, app
from skillguard.reporters import FORMATS

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


def _invoke(*args: str, **kwargs: object):  # noqa: ANN202
    return runner.invoke(app, list(args), **kwargs)


def test_output_format_enum_matches_the_renderers() -> None:
    assert {member.value for member in OutputFormat} == set(FORMATS)


def test_blocked_skill_exits_1() -> None:
    result = _invoke("scan", str(FIXTURES / "malicious_skill"))

    assert result.exit_code == 1
    assert "DO_NOT_INSTALL" in result.stdout


def test_safe_skill_exits_0() -> None:
    result = _invoke("scan", str(FIXTURES / "safe_skill"))

    assert result.exit_code == 0
    assert "SAFE" in result.stdout


def test_low_score_skill_exits_0() -> None:
    result = _invoke("scan", str(FIXTURES / "low_risk_skill"))

    assert result.exit_code == 0
    assert "SC1" in result.stdout


def test_fail_on_findings_blocks_even_a_low_score() -> None:
    result = _invoke("scan", str(FIXTURES / "low_risk_skill"), "--fail-on-findings")

    assert result.exit_code == 1


def test_fail_on_findings_keeps_a_clean_scan_at_0() -> None:
    result = _invoke("scan", str(FIXTURES / "safe_skill"), "--fail-on-findings")

    assert result.exit_code == 0


def test_missing_directory_exits_2() -> None:
    result = _invoke("scan", str(FIXTURES / "does-not-exist"))

    assert result.exit_code == 2


def test_json_goes_to_stdout() -> None:
    result = _invoke("scan", str(FIXTURES / "safe_skill"), "--format", "json")

    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["skill"]["name"] == "safe-demo"
    # LLM review is opt-in: static-only is the default.
    assert payload["metadata"]["llm_requested"] is False


def test_json_written_to_a_file(tmp_path: Path) -> None:
    target = tmp_path / "report.json"
    result = _invoke(
        "scan", str(FIXTURES / "malicious_skill"), "--format", "json", "-o", str(target)
    )

    assert result.exit_code == 1
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["risk_assessment"]["recommendation"] == "DO_NOT_INSTALL"


def test_sarif_format_is_offered() -> None:
    result = _invoke("scan", str(FIXTURES / "safe_skill"), "--format", "sarif")

    assert result.exit_code == 0
    assert json.loads(result.stdout)["version"] == "2.1.0"


def test_no_llm_marks_the_report_as_static_only() -> None:
    result = _invoke("scan", str(FIXTURES / "safe_skill"), "--format", "json", "--no-llm")

    payload = json.loads(result.stdout)

    assert payload["metadata"]["llm_requested"] is False


def test_unknown_format_is_rejected() -> None:
    result = _invoke("scan", str(FIXTURES / "safe_skill"), "--format", "yaml")

    assert result.exit_code == 2


def test_zip_scan_cleans_up_its_temp_directory(tmp_path: Path) -> None:
    archive = tmp_path / "skill.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("SKILL.md", "---\nname: zip-demo\n---\n")
    before = set(Path(tempfile.gettempdir()).glob("skillguard-zip-*"))

    result = _invoke("scan", str(archive))

    assert result.exit_code == 0
    assert set(Path(tempfile.gettempdir()).glob("skillguard-zip-*")) == before


def test_rejected_zip_exits_2(tmp_path: Path) -> None:
    archive = tmp_path / "evil.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../escape.txt", "pwned")

    result = _invoke("scan", str(archive))

    assert result.exit_code == 2
    # Rich wraps at the console width, so compare whitespace-normalised text
    assert "unsafe path in archive" in " ".join(result.stdout.split())


def test_llm_review_is_opt_in(monkeypatch) -> None:  # noqa: ANN001
    # No provider configured: the scan degrades instead of failing.
    monkeypatch.setattr("skillguard.nodes.meta_analyzer.get_reviewer", lambda: None)
    # low_risk_skill has a finding, so the LLM stage actually runs.
    result = _invoke("scan", str(FIXTURES / "low_risk_skill"), "--format", "json", "--llm")

    payload = json.loads(result.stdout)

    assert result.exit_code == 0
    assert payload["metadata"]["llm_requested"] is True
    assert "llm_error" in payload["metadata"]
