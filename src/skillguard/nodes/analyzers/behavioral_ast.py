"""Python AST behavioral analyzer"""

from __future__ import annotations

import ast
from typing import TypeGuard

from skillguard.models import Finding, Location, ScanContext, Severity
from skillguard.nodes.analyzers.common import component_types, snippet_at_line
from skillguard.state import ScanState

# Structural evidence is exact, unlike fuzzy prose regex
_AST_CONFIDENCE = 0.95

_SUBPROCESS_CALLS: frozenset[str] = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "subprocess.getoutput",
        "subprocess.getstatusoutput",
    }
)

# Any os call that hands control to the operating system
_OS_COMMAND_PREFIXES: tuple[str, ...] = ("os.system", "os.popen", "os.exec", "os.spawn")

_DECODERS: tuple[str, ...] = ("b64decode", "urlsafe_b64decode", "decodebytes", "b85decode")
_REMOTE_CALLS: tuple[str, ...] = (
    "requests.get",
    "requests.post",
    "requests.put",
    "urlopen",
    "urllib.request.urlopen",
)

_BUILTINS: frozenset[str] = frozenset({"exec", "eval", "__import__", "compile"})


def _is_literal_str(node: ast.AST | None) -> TypeGuard[ast.Constant]:
    """True when the node is a plain string literal"""
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def resolve_name(node: ast.AST | None) -> str | None:
    """Resolve a Name/Attribute chain: ``os.path.join`` -> ``"os.path.join"``"""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = resolve_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return None


def _is_getattr_call(node: ast.AST | None) -> TypeGuard[ast.Call]:
    """True when this node IS a ``getattr(...)`` call"""
    return (
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "getattr"
    )


def resolve_callee(node: ast.AST | None) -> str | None:
    """Resolve the callable in a call, including the getattr evasion"""
    if _is_getattr_call(node):
        if len(node.args) >= 2:
            base = resolve_name(node.args[0])
            attr = node.args[1]
            if _is_literal_str(attr) and isinstance(attr.value, str):
                return f"{base}.{attr.value}" if base else attr.value
        return None
    return resolve_name(node)


def _has_shell_true(node: ast.Call) -> bool:
    return any(
        keyword.arg == "shell"
        and isinstance(keyword.value, ast.Constant)
        and keyword.value.value is True
        for keyword in node.keywords
    )


def _is_os_command(callee: str | None) -> bool:
    return callee is not None and callee.startswith(_OS_COMMAND_PREFIXES)


def _is_dangerous_target(callee: str | None) -> bool:
    return callee in _SUBPROCESS_CALLS or _is_os_command(callee) or callee in _BUILTINS


def _is_encoded_or_remote(node: ast.AST | None) -> bool:
    """True when a value comes from a decoder or a network call"""
    if isinstance(node, ast.Attribute):
        return _is_encoded_or_remote(node.value)
    if not isinstance(node, ast.Call):
        return False
    callee = resolve_callee(node.func) or ""
    return callee.endswith(_DECODERS) or callee.startswith(_REMOTE_CALLS)


def _finding(
    rule_id: str,
    severity: Severity,
    message: str,
    remediation: str,
    path: str,
    line: int,
    snippet: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category="dangerous_execution",
        severity=severity,
        message=message,
        location=Location(file=path, start_line=max(1, line)),
        snippet=snippet,
        confidence=_AST_CONFIDENCE,
        remediation=remediation,
    )


def _call_findings(node: ast.Call, path: str, text: str) -> list[Finding]:
    """Return every AST rule this one call violates"""
    findings: list[Finding] = []
    callee = resolve_callee(node.func)
    line = node.lineno
    snippet = snippet_at_line(text, line)

    def add(rule_id: str, severity: Severity, message: str, remediation: str) -> None:
        findings.append(_finding(rule_id, severity, message, remediation, path, line, snippet))

    """
        Trigger                                   Severity
        --------                                  -------
AST1	exec(...)	                                CRITICAL
AST2	eval(...)	                                HIGH
AST3	__import__(<non-literal>)	                HIGH
AST4	subprocess.*	                            HIGH
TM1	    subprocess(..., shell=True)	                HIGH
AST5	os.system / os.popen / os.exec* / os.spawn*	HIGH
AST6	compile(...)	                            MEDIUM
AST7	getattr() → dangerous target or computed name	MEDIUM
AST8	exec/eval of decoded/remote data	        CRITICAL
    """

    if callee == "exec":
        add(
            "AST1",
            Severity.CRITICAL,
            "exec() executes arbitrary code",
            "Remove exec(); it runs attacker-controlled code.",
        )
    elif callee == "eval":
        add(
            "AST2",
            Severity.HIGH,
            "eval() evaluates arbitrary expressions",
            "Replace eval() with a safe parser.",
        )
    elif callee == "__import__":
        if not (node.args and _is_literal_str(node.args[0])):
            add(
                "AST3",
                Severity.HIGH,
                "Dynamic import of a computed module name",
                "Use a static import so dependencies stay visible.",
            )
    elif callee == "compile":
        add(
            "AST6",
            Severity.MEDIUM,
            "compile() builds a code object",
            "Avoid compiling untrusted source.",
        )

    if callee in _SUBPROCESS_CALLS:
        add("AST4", Severity.HIGH, "Subprocess execution", "Do not spawn processes from a skill.")
        if _has_shell_true(node):
            add(
                "TM1",
                Severity.HIGH,
                "Shell execution with shell=True",
                "Pass an argument list instead of shell=True.",
            )

    if _is_os_command(callee):
        add(
            "AST5",
            Severity.HIGH,
            "Operating-system command execution",
            "Do not run shell commands from a skill.",
        )

    # AST7 fires on the getattr(...) call itself, so `f = getattr(os,"system")`
    # is caught even when it is never invoked on the same line
    if _is_getattr_call(node):
        attr = node.args[1] if len(node.args) >= 2 else None
        resolved = resolve_callee(node)
        if not _is_literal_str(attr) or _is_dangerous_target(resolved):
            add(
                "AST7",
                Severity.MEDIUM,
                "Dynamic attribute access hides the real call",
                "Reference the attribute directly so it can be reviewed.",
            )

    if callee in {"exec", "eval"} and node.args and _is_encoded_or_remote(node.args[0]):
        add(
            "AST8",
            Severity.CRITICAL,
            "Execution of a decoded or remote payload",
            "Remove encoded execution; it hides what actually runs",
        )

    return findings


def analyze_python(context: ScanContext) -> list[Finding]:
    """Walk every cached Python file and report structural risks"""
    findings: list[Finding] = []
    types = component_types(context)

    for path, text in context.file_cache.items():
        if types.get(path) != "python":
            continue
        try:
            tree = ast.parse(text, filename=path)
        except (SyntaxError, ValueError):
            # Unparseable Python is still covered by the regex analyzers.
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                findings.extend(_call_findings(node, path, text))

    return findings


def behavioral_ast(state: ScanState) -> dict[str, object]:
    """Analyzer node: structural Python analysis"""
    context = state.get("context")
    if context is None:
        return {"findings": []}
    return {"findings": analyze_python(context)}
