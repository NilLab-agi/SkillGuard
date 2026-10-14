"""Phase 11: verdict merging, graceful degradation, and the trust model."""

from __future__ import annotations

from pathlib import Path

from skillguard.models import Finding, Location, Severity
from skillguard.nodes.meta_analyzer import (
    apply_verdicts,
    build_request,
    evidence_for,
    meta_analyzer,
)
from skillguard.pipeline import initial_state, run_scan
from skillguard.providers.base import ReviewRequest, Verdict
from skillguard.state import ScanState

FIXTURES = Path(__file__).parent / "fixtures"


def _finding(rule_id: str = "P1", severity: Severity = Severity.HIGH) -> Finding:
    return Finding(
        rule_id=rule_id,
        category="prompt_injection",
        severity=severity,
        message="Instruction override attempt",
        location=Location(file="SKILL.md", start_line=3),
        confidence=0.6,
    )


class FakeReviewer:
    """Stands in for a provider. Records what it was asked to review."""

    def __init__(
        self, verdicts: list[Verdict] | None = None, error: Exception | None = None
    ) -> None:
        self.verdicts = verdicts or []
        self.error = error
        self.requests: list[ReviewRequest] = []

    def review(self, request: ReviewRequest) -> list[Verdict]:
        self.requests.append(request)
        if self.error is not None:
            raise self.error
        return self.verdicts


# ------------------------------------------------------------ apply_verdicts


def test_a_verdict_adds_an_explanation_and_can_raise_confidence() -> None:
    findings = [_finding()]
    verdicts = [Verdict("P1", "SKILL.md", 3, "confirmed", "clearly an override", 0.95)]

    reviewed = apply_verdicts(findings, verdicts)

    assert reviewed[0].llm_outcome == "confirmed"
    assert reviewed[0].llm_explanation == "clearly an override"
    assert reviewed[0].confidence == 0.95


def test_a_verdict_can_never_drop_a_finding() -> None:
    findings = [_finding("P1"), _finding("P2"), _finding("E2")]

    reviewed = apply_verdicts(findings, [Verdict("P1", "SKILL.md", 3, "disputed")])

    assert len(reviewed) == 3
    assert [f.rule_id for f in reviewed] == ["P1", "P2", "E2"]


def test_no_verdicts_at_all_changes_nothing() -> None:
    findings = [_finding()]

    assert apply_verdicts(findings, []) == findings


def test_a_verdict_can_never_lower_confidence() -> None:
    findings = [_finding()]
    verdicts = [Verdict("P1", "SKILL.md", 3, "disputed", "not sure", 0.05)]

    reviewed = apply_verdicts(findings, verdicts)

    assert reviewed[0].confidence == 0.6  # unchanged, not 0.05


def test_a_verdict_can_never_change_severity() -> None:
    findings = [_finding(severity=Severity.CRITICAL)]
    verdicts = [Verdict("P1", "SKILL.md", 3, "disputed", "probably fine", 0.1)]

    reviewed = apply_verdicts(findings, verdicts)

    assert reviewed[0].severity is Severity.CRITICAL


def test_a_verdict_for_an_unknown_finding_is_ignored() -> None:
    findings = [_finding("P1")]
    verdicts = [Verdict("ZZ9", "other.md", 99, "confirmed")]

    reviewed = apply_verdicts(findings, verdicts)

    assert len(reviewed) == 1
    assert reviewed[0].llm_outcome is None


def test_verdicts_are_matched_on_rule_file_and_line() -> None:
    findings = [_finding("P1"), _finding("P2")]
    verdicts = [Verdict("P2", "SKILL.md", 3, "confirmed", "this one")]

    reviewed = apply_verdicts(findings, verdicts)

    assert reviewed[0].llm_outcome is None
    assert reviewed[1].llm_outcome == "confirmed"


# ------------------------------------------------------------- the node


def _state(use_llm: bool = True) -> ScanState:
    context = run_scan(initial_state(str(FIXTURES / "jailbreak_skill")))["context"]
    return ScanState(context=context, use_llm=use_llm, effective_findings=list(context and []))  # type: ignore[typeddict-item]


def test_node_passes_through_when_llm_is_not_requested() -> None:
    context = run_scan(initial_state(str(FIXTURES / "jailbreak_skill")))["context"]
    findings = [_finding()]
    state = ScanState(context=context, use_llm=False, effective_findings=findings)

    update = meta_analyzer(state)

    assert update["effective_findings"] == findings
    assert "llm_error" not in update


def test_node_degrades_when_no_provider_is_configured(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr("skillguard.nodes.meta_analyzer.get_reviewer", lambda: None)
    context = run_scan(initial_state(str(FIXTURES / "jailbreak_skill")))["context"]
    findings = [_finding()]
    state = ScanState(context=context, use_llm=True, effective_findings=findings)

    update = meta_analyzer(state)

    assert update["effective_findings"] == findings
    assert "no LLM provider configured" in str(update["llm_error"])


def test_node_degrades_when_the_reviewer_raises(monkeypatch) -> None:  # noqa: ANN001
    monkeypatch.setattr(
        "skillguard.nodes.meta_analyzer.get_reviewer",
        lambda: FakeReviewer(error=RuntimeError("connection reset")),
    )
    context = run_scan(initial_state(str(FIXTURES / "jailbreak_skill")))["context"]
    findings = [_finding()]
    state = ScanState(context=context, use_llm=True, effective_findings=findings)

    update = meta_analyzer(state)

    assert update["effective_findings"] == findings
    assert "RuntimeError" in str(update["llm_error"])


def test_node_applies_verdicts_from_the_reviewer(monkeypatch) -> None:  # noqa: ANN001
    reviewer = FakeReviewer([Verdict("P1", "SKILL.md", 3, "confirmed", "yes", 0.9)])
    monkeypatch.setattr("skillguard.nodes.meta_analyzer.get_reviewer", lambda: reviewer)
    context = run_scan(initial_state(str(FIXTURES / "jailbreak_skill")))["context"]
    findings = [_finding()]
    state = ScanState(context=context, use_llm=True, effective_findings=findings)

    update = meta_analyzer(state)
    reviewed = update["effective_findings"]

    assert isinstance(reviewed, list)
    assert reviewed[0].llm_outcome == "confirmed"
    assert reviewer.requests and reviewer.requests[0].findings == tuple(findings)


def test_node_skips_the_model_when_there_is_nothing_to_review(monkeypatch) -> None:  # noqa: ANN001
    reviewer = FakeReviewer([Verdict("P1", "SKILL.md", 3, "confirmed")])
    monkeypatch.setattr("skillguard.nodes.meta_analyzer.get_reviewer", lambda: reviewer)
    context = run_scan(initial_state(str(FIXTURES / "jailbreak_skill")))["context"]
    state = ScanState(context=context, use_llm=True, effective_findings=[])

    update = meta_analyzer(state)

    assert update["effective_findings"] == []
    assert reviewer.requests == []


# ------------------------------------------------------------- evidence


def test_evidence_is_a_bounded_window_not_the_whole_file() -> None:
    context = run_scan(initial_state(str(FIXTURES / "jailbreak_skill")))["context"]
    finding = Finding(
        rule_id="P1",
        category="prompt_injection",
        severity=Severity.HIGH,
        message="m",
        location=Location(file="SKILL.md", start_line=8),
    )

    evidence = evidence_for(context, [finding])

    assert len(evidence) == 1
    assert len(evidence[0].text.splitlines()) <= 13
    assert evidence[0].start_line >= 1


def test_evidence_deduplicates_one_location() -> None:
    context = run_scan(initial_state(str(FIXTURES / "jailbreak_skill")))["context"]
    same = Location(file="SKILL.md", start_line=8)
    findings = [
        Finding(rule_id="P1", category="c", severity=Severity.HIGH, message="a", location=same),
        Finding(rule_id="P2", category="c", severity=Severity.HIGH, message="b", location=same),
    ]

    assert len(evidence_for(context, findings)) == 1


def test_build_request_carries_findings_and_evidence() -> None:
    context = run_scan(initial_state(str(FIXTURES / "jailbreak_skill")))["context"]
    findings = [_finding()]

    request = build_request(findings, context)

    assert request.findings == tuple(findings)
    assert request.evidence
