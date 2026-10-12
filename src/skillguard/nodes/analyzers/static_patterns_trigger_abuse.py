"""Trigger abuse rules. Over broad or shadowing skill metadata"""

from __future__ import annotations

import re

from skillguard.models import Severity
from skillguard.nodes.analyzers.pattern_defaults import PROSE_TYPES, rule

rule(
    id="TR1",
    category="trigger_abuse",
    severity=Severity.LOW,
    message="Overly broad trigger description",
    pattern=re.compile(
        r"^[ \t]*(?:description|trigger|when)[ \t]*[:=][^\n]{0,100}"
        r"\b(?:anything|everything|any\s+task|always|whenever|all\s+requests?)\b",
        re.IGNORECASE | re.MULTILINE,
    ),
    remediation="Describe a specific trigger so the skill is not always selected.",
    confidence=0.6,
    file_types=PROSE_TYPES,
)

rule(
    id="TR2",
    category="trigger_abuse",
    severity=Severity.MEDIUM,
    message="Skill name shadows a built-in tool",
    pattern=re.compile(
        r"^[ \t]*(?:name|tool)[ \t]*[:=][ \t]*"
        r"(?:run|exec|execute|shell|bash|read|write|edit|search|grep)[ \t]*$",
        re.IGNORECASE | re.MULTILINE,
    ),
    remediation="Rename the skill/tool so it cannot shadow a built-in capability.",
    confidence=0.7,
    file_types=PROSE_TYPES,
)

CATEGORY: str = "trigger_abuse"
NODE_NAME: str = "static_trigger_abuse"
