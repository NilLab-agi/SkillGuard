"""Prompt-injection rules. These read PROSE, never code"""

from __future__ import annotations

import re

from skillguard.models import Severity
from skillguard.nodes.analyzers.pattern_defaults import PROSE_TYPES, rule

rule(
    id="P1",
    category="prompt_injection",
    severity=Severity.HIGH,
    message="Instruction override attempt",
    # re.IGNORECASE: attackers change case to dodge naive matchers.
    pattern=re.compile(
        r"\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+"
        r"(instructions?|prompts?|rules?|directives?)\b",
        re.IGNORECASE,
    ),
    remediation="Remove instructions that try to override the agent's safety rules.",
    confidence=0.85,
    file_types=PROSE_TYPES,
)

rule(
    id="P2",
    category="prompt_injection",
    severity=Severity.HIGH,
    message="Instruction to hide behaviour from the user",
    pattern=re.compile(
        r"\bdo\s+not\s+(tell|inform|notify|show|reveal|mention)\s+(the\s+)?user\b",
        re.IGNORECASE,
    ),
    remediation="Remove concealment instructions; behaviour must be visible to the user",
    confidence=0.85,
    file_types=PROSE_TYPES,
)

rule(
    id="P3",
    category="prompt_injection",
    severity=Severity.HIGH,
    message="Instruction to transmit data to an external endpoint",
    pattern=re.compile(
        r"\b(send|post|upload|transmit|exfiltrate)\b[^\n]{0,40}\b(to|at)\b[^\n]{0,40}https?://",
        re.IGNORECASE,
    ),
    remediation="Do not follow instructions that send data to external endpoints.",
    confidence=0.8,
    file_types=PROSE_TYPES,
)

CATEGORY: str = "prompt_injection"
NODE_NAME: str = "static_prompt_injection"
