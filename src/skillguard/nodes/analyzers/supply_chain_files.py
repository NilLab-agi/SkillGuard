"""File-shape rules: SC8 shipped bytecode, SC9 disguised executable."""

from __future__ import annotations

from pathlib import Path

from skillguard.constants import (
    EXECUTABLE_EXTENSIONS,
    SHIPPED_BYTECODE_REASON,
)
from skillguard.models import Finding, Location, Severity
from skillguard.state import ScanState

_CATEGORY = "supply_chain"

#: Extensions that make a file look harmless when it is not.
_DISGUISING_SUFFIXES: frozenset[str] = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".webp",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
        ".txt",
        ".csv",
        ".json",
        ".xml",
        ".zip",
        ".tar",
        ".gz",
        ".mp3",
        ".mp4",
        ".wav",
        ".mov",
    }
)


def _finding(
    rule_id: str, message: str, remediation: str, confidence: float, path: str, snippet: str
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=_CATEGORY,
        severity=Severity.HIGH,
        message=message,
        location=Location(file=path, start_line=1),
        snippet=snippet,
        confidence=confidence,
        remediation=remediation,
    )


def _bytecode_findings(components: list[str], skipped: list[tuple[str, str]]) -> list[Finding]:
    findings: list[Finding] = []
    for path, reason in skipped:
        if reason == SHIPPED_BYTECODE_REASON:
            findings.append(
                _finding(
                    "SC8",
                    "Compiled Python bytecode is shipped in the skill",
                    "Remove __pycache__; bytecode is unreadable and can hide code.",
                    0.9,
                    path,
                    path,
                )
            )
    for path in components:
        if Path(path).suffix.lower() in {".pyc", ".pyo"}:
            findings.append(
                _finding(
                    "SC8",
                    "Compiled Python bytecode is shipped in the skill",
                    "Remove .pyc files; bytecode is unreadable and can hide code.",
                    0.9,
                    path,
                    path,
                )
            )
    return findings


def _disguised_findings(components: list[str]) -> list[Finding]:
    findings: list[Finding] = []
    for path in components:
        name = Path(path)
        if name.suffix.lower() not in EXECUTABLE_EXTENSIONS:
            continue
        # "logo.png.py" -> stem "logo.png" -> suffix ".png"
        if Path(name.stem).suffix.lower() in _DISGUISING_SUFFIXES:
            findings.append(
                _finding(
                    "SC9",
                    f"Executable disguised as a document: '{path}'",
                    "Rename the file so its extension matches what it does.",
                    0.9,
                    path,
                    path,
                )
            )
    return findings


def supply_chain_files(state: ScanState) -> dict[str, object]:
    """Analyzer node: shipped bytecode and disguised executables."""
    context = state.get("context")
    if context is None:
        return {"findings": []}

    components = [component.path for component in context.components]
    findings = _bytecode_findings(components, list(context.skipped))
    findings.extend(_disguised_findings(components))
    return {"findings": findings}
