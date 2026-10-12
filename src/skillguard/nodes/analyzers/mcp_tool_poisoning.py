"""MCP tool poisoning analyzer

Tool and parameter descriptions are read by the model, so they are an injection
surface: text can be hidden, disguised, or contradict what the tool does.
"""

from __future__ import annotations

import re

from skillguard.models import Finding, Location, Severity
from skillguard.nodes.analyzers.mcp_config import McpTool, load_mcp_servers
from skillguard.state import ScanState

_CATEGORY = "mcp_tool_poisoning"

#: Invisible characters used to smuggle text past a human reviewer.
_HIDDEN_CHARS: dict[str, str] = {
    "\u200b": "zero-width space",
    "\u200c": "zero-width non-joiner",
    "\u200d": "zero-width joiner",
    "\u2060": "word joiner",
    "\ufeff": "zero-width no-break space",
}

#: Direction-control characters that reorder how text is displayed.
_BIDI_CHARS: dict[str, str] = {
    "\u202a": "left-to-right embedding",
    "\u202b": "right-to-left embedding",
    "\u202d": "left-to-right override",
    "\u202e": "right-to-left override",
    "\u2066": "left-to-right isolate",
    "\u2067": "right-to-left isolate",
}

# A deliberately small homoglyph map: Cyrillic letters that look Latin
_HOMOGLYPHS: dict[str, str] = {
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "ѕ": "s",
    "ԁ": "d",
    "А": "A",
    "Е": "E",
    "О": "O",
    "Р": "P",
}

_HTML_COMMENT = re.compile(r"<!--.*?-->", re.DOTALL)
_DATA_URI = re.compile(r"data:[^\s;]{0,40};base64,", re.IGNORECASE)

# Instruction shapes that do not belong in a parameter description
_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("instruction override", re.compile(r"\bignore\s+(all\s+)?(previous|prior|above)\b", re.I)),
    ("concealment", re.compile(r"\bdo\s+not\s+(tell|inform|reveal|notify)\b", re.I)),
    (
        "data transmission",
        re.compile(r"\b(send|post|upload|exfiltrate)\b[^\n]{0,40}https?://", re.I),
    ),
    ("refusal suppression", re.compile(r"\b(never|do\s+not)\s+refuse\b", re.I)),
)


def _hidden_reason(text: str) -> str | None:
    for char, label in _HIDDEN_CHARS.items():
        if char in text:
            return label
    if _HTML_COMMENT.search(text):
        return "HTML comment"
    if _DATA_URI.search(text):
        return "base64 data URI"
    return None


def _deception_reason(text: str) -> str | None:
    for char, label in _BIDI_CHARS.items():
        if char in text:
            return label
    # Homoglyphs alone are just another language; mixed with ASCII they disguise.
    mixed_script = any(char in text for char in _HOMOGLYPHS) and any(
        char.isascii() and char.isalpha() for char in text
    )
    if mixed_script:
        for char, latin in _HOMOGLYPHS.items():
            if char in text:
                return f"lookalike {char!r} for {latin!r}"
    return None


def _injection_reason(text: str) -> str | None:
    for label, pattern in _INJECTION_PATTERNS:
        if pattern.search(text):
            return label
    return None


def _finding(
    rule_id: str,
    message: str,
    remediation: str,
    confidence: float,
    tool: McpTool,
    snippet: str,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=_CATEGORY,
        severity=Severity.HIGH,
        message=message,
        location=Location(file=tool.source, start_line=tool.line),
        snippet=snippet.strip()[:160],
        confidence=confidence,
        remediation=remediation,
    )


def _tool_findings(tool: McpTool) -> list[Finding]:
    findings: list[Finding] = []
    descriptions = (tool.description, *tool.parameter_descriptions)

    for text in descriptions:
        reason = _hidden_reason(text)
        if reason:
            findings.append(
                _finding(
                    "TP1",
                    f"Hidden content in the description of '{tool.name}' ({reason})",
                    "Remove hidden characters; a description must read as it appears.",
                    0.95,
                    tool,
                    text,
                )
            )
            break

    for text in descriptions:
        reason = _deception_reason(text)
        if reason:
            findings.append(
                _finding(
                    "TP2",
                    f"Unicode deception in the description of '{tool.name}' ({reason})",
                    "Use plain text with no lookalike or direction-control characters.",
                    0.9,
                    tool,
                    text,
                )
            )
            break

    for text in tool.parameter_descriptions:
        reason = _injection_reason(text)
        if reason:
            findings.append(
                _finding(
                    "TP3",
                    f"Instruction-like text in a parameter description of '{tool.name}' ({reason})",
                    "Parameter descriptions describe the parameter, not the model.",
                    0.85,
                    tool,
                    text,
                )
            )
            break

    return findings


def mcp_tool_poisoning(state: ScanState) -> dict[str, object]:
    """Analyzer node: poisoned tool and parameter descriptions."""
    context = state.get("context")
    if context is None:
        return {"findings": []}
    return {
        "findings": [
            finding
            for server in load_mcp_servers(context)
            for tool in server.tools
            for finding in _tool_findings(tool)
        ]
    }
