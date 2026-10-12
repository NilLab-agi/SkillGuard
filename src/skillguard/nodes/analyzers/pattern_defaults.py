"""Rule definition and the global rule registry"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from skillguard.models import Severity

#: File types whose *prose* may carry instructions. Code rules must not use this.
PROSE_TYPES: frozenset[str] = frozenset({"markdown", "text", "yaml", "other"})

#: File types whose *code* may execute.
CODE_TYPES: frozenset[str] = frozenset({"python", "shell", "javascript", "typescript"})


@dataclass(frozen=True, slots=True)
class Rule:
    """One static check. Frozen because rules never change after registration"""

    id: str
    category: str
    severity: Severity
    message: str
    pattern: re.Pattern[str]
    remediation: str
    confidence: float = 0.8
    #: Component types this rule applies to. Empty = every text file.
    file_types: frozenset[str] = field(default_factory=frozenset)


#: Every registered rule, in registration order.
REGISTRY: list[Rule] = []


def rule(
    *,
    id: str,
    category: str,
    severity: Severity,
    message: str,
    pattern: re.Pattern[str],
    remediation: str,
    confidence: float = 0.8,
    file_types: frozenset[str] = frozenset(),  # immutable, so a shared default is safe
) -> Rule:
    """Register one rule. Called at module import time"""
    if any(existing.id == id for existing in REGISTRY):
        raise ValueError(f"duplicate rule id: {id}")

    registered = Rule(
        id=id,
        category=category,
        severity=severity,
        message=message,
        pattern=pattern,
        remediation=remediation,
        confidence=confidence,
        file_types=file_types,
    )
    REGISTRY.append(registered)
    return registered


def rules_for(category: str) -> tuple[Rule, ...]:
    """Return every rule in one category"""
    return tuple(entry for entry in REGISTRY if entry.category == category)
