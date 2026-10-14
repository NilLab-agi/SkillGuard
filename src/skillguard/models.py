"""The vocabulary of a scan.

Every value that flows through the pipeline is defined here once. Pydantic
turns these type hints into runtime validation and free JSON serialization,
which is what makes the report a contract instead of a printf
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from skillguard.constants import SCANNER_VERSION


class Severity(StrEnum):
    """Risk band of a single finding, ordered least to most dangerous."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Recommendation(StrEnum):
    """What the user should do with the scanned skill."""

    SAFE = "SAFE"
    CAUTION = "CAUTION"
    DO_NOT_INSTALL = "DO_NOT_INSTALL"


# Points contributed to the risk score by one finding of each severity
SEVERITY_POINTS: dict[Severity, int] = {
    Severity.LOW: 5,
    Severity.MEDIUM: 10,
    Severity.HIGH: 25,
    Severity.CRITICAL: 50,
}


class Location(BaseModel):
    """Where a finding was observed, as a path relative to the skill root"""

    model_config = ConfigDict(frozen=True)

    file: str
    start_line: int = Field(ge=1)


class Finding(BaseModel):
    """One security observation, produced by exactly one analyzer (rule)"""

    model_config = ConfigDict(frozen=True)

    rule_id: str  # stable machine id, e.g. "PI1"
    category: str  # grouping for reports, e.g. "prompt_injection"
    severity: Severity
    message: str  # human-readable description of the finding
    location: Location
    snippet: str = ""  # the matched text, used as evidence
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    remediation: str = ""  # what to do about it
    llm_outcome: str | None = None  # confirmed | disputed | unclear
    llm_explanation: str = ""  # model supplied context, never a replacement


class Component(BaseModel):
    """One file discovered inside the skill"""

    path: str
    type: str  # python | markdown | shell | json | yaml | requirements | binary
    lines: int = Field(default=0, ge=0)
    executable: bool = False
    size_bytes: int = Field(default=0, ge=0)


class ScanContext(BaseModel):
    """Everything the analyzers need about one skill, built once and shared"""

    skill_path: str
    components: list[Component] = Field(default_factory=list)
    file_cache: dict[str, str] = Field(default_factory=dict)  # path -> file content
    manifest: dict[str, object] = Field(default_factory=dict)  # skill metadata: parsed SKILL.md
    has_executable_scripts: bool = False
    skipped: list[tuple[str, str]] = Field(default_factory=list)  # (path, reason)


class RiskAssessment(BaseModel):
    """The headline: score, band, and what the user should do"""

    score: int = Field(ge=0, le=100)

    severity: Severity
    recommendation: Recommendation


class Report(BaseModel):
    skill_name: str
    source: str
    scanned_at: str
    components: list[Component] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    risk: RiskAssessment
    has_executable_scripts: bool = False
    llm_requested: bool = False
    llm_error: str | None = None
    suppressed_findings: list[Finding] = Field(default_factory=list)
    scanner_version: str = SCANNER_VERSION
