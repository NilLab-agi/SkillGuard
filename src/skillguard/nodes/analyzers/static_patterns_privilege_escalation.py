"""Privilege escalation rules"""

from __future__ import annotations

import re

from skillguard.models import Severity
from skillguard.nodes.analyzers.pattern_defaults import CODE_TYPES, rule

rule(
    id="PE1",
    category="privilege_escalation",
    severity=Severity.MEDIUM,
    message="World-writable permissions",
    pattern=re.compile(r"\bchmod\s+(?:-R\s+)?(?:777|a\+rwx)\b", re.IGNORECASE),
    remediation="Use the narrowest permissions; 777 lets any user modify the file.",
    confidence=0.9,
    file_types=CODE_TYPES,
)

rule(
    id="PE2",
    category="privilege_escalation",
    severity=Severity.MEDIUM,
    message="Elevated privilege execution",
    pattern=re.compile(r"\bsudo\b|\bsu\s+-c\b", re.IGNORECASE),
    remediation="Do not require root; ask the user to run privileged steps themselves.",
    confidence=0.8,
    file_types=CODE_TYPES,
)

rule(
    id="PE3",
    category="privilege_escalation",
    severity=Severity.HIGH,
    message="Credential file access",
    # No file_types: a *path* is meaningful in prose ("read ~/.ssh/id_rsa") too.
    pattern=re.compile(
        r"\b(?:id_rsa|id_ed25519|\.aws/credentials|\.netrc|/etc/shadow)\b", re.IGNORECASE
    ),
    remediation="Never read private keys or credential stores.",
    confidence=0.9,
)

CATEGORY: str = "privilege_escalation"
NODE_NAME: str = "static_privilege_escalation"
