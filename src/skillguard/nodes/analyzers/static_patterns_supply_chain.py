"""Supply chain rules. Unpinned deps and remote code execution"""

from __future__ import annotations

import re

from skillguard.models import Severity
from skillguard.nodes.analyzers.pattern_defaults import CODE_TYPES, rule

rule(
    id="SC2",
    category="supply_chain",
    severity=Severity.HIGH,
    message="Remote script piped into a shell",
    # [^\n|] stops the match from crossing a pipe or a line, which keeps it tight.
    pattern=re.compile(r"\b(?:curl|wget)\b[^\n|]{0,100}\|\s*(?:ba|z|k)?sh\b", re.IGNORECASE),
    remediation="Download, inspect, then run; never pipe a remote script into a shell.",
    confidence=0.9,
    file_types=CODE_TYPES,
)

rule(
    id="SC3",
    category="supply_chain",
    severity=Severity.HIGH,
    message="Decoded payload executed",
    pattern=re.compile(
        r"\bbase64\s+(?:-d|--decode)\b[^\n|]{0,60}\|\s*(?:ba)?sh\b|eval\s*\(\s*base64",
        re.IGNORECASE,
    ),
    remediation="Remove encoded execution; it hides what actually runs.",
    confidence=0.9,
    file_types=CODE_TYPES,
)

CATEGORY: str = "supply_chain"
NODE_NAME: str = "static_supply_chain"
