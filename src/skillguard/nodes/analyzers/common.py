"""Helpers shared by the static runner.

Small on purpose: line mapping and snippet extraction are the only things a
regex analyzer needs to turn a match into an actionable Finding.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

from skillguard.models import ScanContext


def line_of(text: str, index: int) -> int:
    """Return the 1 based line number containing character ``index``"""
    return text.count("\n", 0, index) + 1


def snippet_for(text: str, match: re.Match[str], *, max_len: int = 160) -> str:
    """Return the trimmed line containing the match, for use as evidence"""
    line_start = text.rfind("\n", 0, match.start()) + 1
    line_end = text.find("\n", match.end())
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()[:max_len]


def component_types(context: ScanContext) -> dict[str, str]:
    """Map component path -> type, so we can filter files by type"""
    return {component.path: component.type for component in context.components}


def iter_eligible_files(
    context: ScanContext, file_types: frozenset[str]
) -> Iterator[tuple[str, str]]:
    """Yield (path, text) for cached files whose type the rule applies to.

    ``file_types`` empty means every text file. file_cache is already in sorted
    walk order, so output is deterministic
    """
    types = component_types(context)
    for path, text in context.file_cache.items():
        if not file_types or types.get(path, "other") in file_types:
            yield path, text


def snippet_at_line(text: str, line: int, *, max_len: int = 160) -> str:
    """Return the trimmed text of a 1 based line number"""
    lines = text.splitlines()
    if not 1 <= line <= len(lines):
        return ""
    return lines[line - 1].strip()[:max_len]
