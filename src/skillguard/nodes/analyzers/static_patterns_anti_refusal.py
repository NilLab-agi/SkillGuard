"""Anti refusal rules. Prose that disables safety behaviour"""

from __future__ import annotations

import re

from skillguard.models import Severity
from skillguard.nodes.analyzers.pattern_defaults import PROSE_TYPES, rule

rule(
    id="AR1",
    category="anti_refusal",
    severity=Severity.HIGH,
    message="Refusal suppression",
    pattern=re.compile(r"\b(never|do\s+not|don't)\s+refuse\b", re.IGNORECASE),
    remediation="Remove instructions that forbid refusing requests.",
    confidence=0.85,
    file_types=PROSE_TYPES,
)

rule(
    id="AR2",
    category="anti_refusal",
    severity=Severity.HIGH,
    message="Disclaimer or warning suppression",
    pattern=re.compile(
        r"\b(no|without|skip|omit|do\s+not\s+add|don't\s+add)\s+"
        r"(disclaimers?|warnings?|caveats?|ethical\s+commentary)\b",
        re.IGNORECASE,
    ),
    remediation="Do not suppress warnings or disclaimers about risky output.",
    confidence=0.8,
    file_types=PROSE_TYPES,
)

rule(
    id="AR3",
    category="anti_refusal",
    severity=Severity.HIGH,
    message="Safety policy nullification",
    pattern=re.compile(
        r"\b(ignore|disregard|forget|override)\s+(your\s+)?"
        r"(safety|guidelines?|restrictions?|polic(?:y|ies)|guardrails?)\b",
        re.IGNORECASE,
    ),
    remediation="Remove instructions that nullify the agent's safety policy.",
    confidence=0.85,
    file_types=PROSE_TYPES,
)

CATEGORY: str = "anti_refusal"
NODE_NAME: str = "static_anti_refusal"
