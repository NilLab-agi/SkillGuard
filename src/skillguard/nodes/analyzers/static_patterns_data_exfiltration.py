"""Data exfiltration rules. Code that collects and ships data out"""

from __future__ import annotations

import re

from skillguard.models import Severity
from skillguard.nodes.analyzers.pattern_defaults import CODE_TYPES, rule

rule(
    id="E1",
    category="data_exfiltration",
    severity=Severity.HIGH,
    message="External transmission of data",
    # Matches the call, not the URL: the URL alone is not evidence on its own.
    pattern=re.compile(
        r"\b(requests\.(?:post|put|patch)|httpx\.(?:post|put|patch)|"
        r"urllib\.request\.urlopen|urlopen)\s*\(",
        re.IGNORECASE,
    ),
    remediation="Do not send data to external endpoints; keep it local.",
    confidence=0.75,
    file_types=CODE_TYPES,
)

rule(
    id="E2",
    category="data_exfiltration",
    severity=Severity.HIGH,
    message="Environment variable harvesting",
    pattern=re.compile(
        r"os\.environ\b[^\n]{0,40}\b(?:items|keys|values|copy|dict)\s*\(|printenv\b",
        re.IGNORECASE,
    ),
    remediation="Read only the environment variable you need, never all of them.",
    confidence=0.9,
    file_types=CODE_TYPES,
)

rule(
    id="E3",
    category="data_exfiltration",
    severity=Severity.MEDIUM,
    message="Environment file access",
    pattern=re.compile(
        r"\b(?:load_dotenv|dotenv)\s*\(|\bopen\s*\([^\n)]{0,40}\.env\b",
        re.IGNORECASE,
    ),
    remediation="Do not read .env files; they hold secrets.",
    confidence=0.7,
    file_types=CODE_TYPES,
)

rule(
    id="E4",
    category="data_exfiltration",
    severity=Severity.HIGH,
    message="Shell upload of data to an external host",
    pattern=re.compile(r"\b(?:curl|wget)\b[^\n|]{0,60}(?:-d|--data|--post-data)\b", re.IGNORECASE),
    remediation="Do not upload data with curl/wget from a skill.",
    confidence=0.8,
    file_types=CODE_TYPES,
)

CATEGORY: str = "data_exfiltration"
NODE_NAME: str = "static_data_exfiltration"
