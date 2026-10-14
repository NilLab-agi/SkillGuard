"""The reviewer contract.

A reviewer looks at findings and returns verdicts about them. It is a Protocol,
not a base class, so a fake reviewer in tests needs no inheritance and a second
provider needs no change here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from skillguard.models import Finding

#: What the model may conclude about one finding.
Outcome = Literal["confirmed", "disputed", "unclear"]


@dataclass(frozen=True, slots=True)
class Verdict:
    """One model judgement about one finding."""

    rule_id: str
    file: str
    line: int
    outcome: Outcome
    explanation: str = ""
    confidence: float = 0.8


@dataclass(frozen=True, slots=True)
class Evidence:
    """The source lines a finding points at, so the model can judge intent."""

    file: str
    start_line: int
    text: str


@dataclass(frozen=True, slots=True)
class ReviewRequest:
    """Everything the reviewer is allowed to see."""

    findings: tuple[Finding, ...]
    evidence: tuple[Evidence, ...]


class Reviewer(Protocol):
    """Anything that can review findings."""

    def review(self, request: ReviewRequest) -> list[Verdict]: ...
