"""LLM semantic review of findings.

The trust model in one sentence: the model may ADD context and may RAISE
confidence, but it may never remove a finding, lower a severity, or lower a
confidence. ``apply_verdicts`` enforces that structurally, not by convention.
"""

from __future__ import annotations

from skillguard.config import get_settings
from skillguard.models import Finding, ScanContext
from skillguard.providers.base import Evidence, Reviewer, ReviewRequest, Verdict
from skillguard.providers.registry import build_reviewer, is_configured
from skillguard.state import ScanState

#: Lines of context around each finding, so the model can judge intent.
_EVIDENCE_RADIUS = 6


def get_reviewer() -> Reviewer | None:
    """Build the reviewer from settings. Tests monkeypatch this function."""
    settings = get_settings()
    if not is_configured(settings):
        return None
    return build_reviewer(settings)


def _window(text: str, line: int, *, radius: int = _EVIDENCE_RADIUS) -> str:
    lines = text.splitlines()
    start = max(0, line - 1 - radius)
    end = min(len(lines), line + radius)
    return "\n".join(lines[start:end])


def evidence_for(context: ScanContext, findings: list[Finding]) -> tuple[Evidence, ...]:
    """Extract a small window of source text around each finding.

    A window, not the whole file: fewer tokens, and less untrusted text in the
    prompt for an attacker to hide instructions in.
    """
    seen: set[tuple[str, int]] = set()
    evidence: list[Evidence] = []
    for finding in findings:
        key = (finding.location.file, finding.location.start_line)
        if key in seen:
            continue
        seen.add(key)
        text = context.file_cache.get(finding.location.file)
        if text is None:
            continue
        evidence.append(
            Evidence(
                file=finding.location.file,
                start_line=max(1, finding.location.start_line - _EVIDENCE_RADIUS),
                text=_window(text, finding.location.start_line),
            )
        )
    return tuple(evidence)


def build_request(findings: list[Finding], context: ScanContext) -> ReviewRequest:
    """Assemble everything the reviewer may see."""
    return ReviewRequest(findings=tuple(findings), evidence=evidence_for(context, findings))


def apply_verdicts(findings: list[Finding], verdicts: list[Verdict]) -> list[Finding]:
    """Attach verdicts without ever dropping or downgrading a finding.

    Two structural guarantees:
    - the result is built by iterating the INPUT findings, so the count can
      only stay the same; a verdict for an unknown finding is ignored;
    - the update dict has no ``severity`` key, so no code path can lower one,
      and confidence goes through ``max`` so it can only rise.
    """
    by_key = {(verdict.rule_id, verdict.file, verdict.line): verdict for verdict in verdicts}

    reviewed: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.location.file, finding.location.start_line)
        verdict = by_key.get(key)
        if verdict is None:
            reviewed.append(finding)
            continue
        reviewed.append(
            finding.model_copy(
                update={
                    "llm_outcome": verdict.outcome,
                    "llm_explanation": verdict.explanation,
                    "confidence": max(finding.confidence, verdict.confidence),
                }
            )
        )
    return reviewed


def meta_analyzer(state: ScanState) -> dict[str, object]:
    """Review findings with a model, or pass them through untouched."""
    findings = list(state.get("effective_findings", []))

    if not state.get("use_llm"):
        return {"effective_findings": findings}

    context = state.get("context")
    if context is None or not findings:
        return {"effective_findings": findings}

    reviewer = get_reviewer()
    if reviewer is None:
        return {
            "effective_findings": findings,
            "llm_error": (
                "no LLM provider configured (set SKILLGUARD_API_KEY or SKILLGUARD_BASE_URL)"
            ),
        }

    try:
        verdicts = reviewer.review(build_request(findings, context))
    except Exception as exc:  # any provider failure must degrade, not abort
        # Degrade, never fail the scan: the deterministic findings are still valid.
        return {
            "effective_findings": findings,
            "llm_error": f"{type(exc).__name__}: {exc}",
        }

    return {"effective_findings": apply_verdicts(findings, verdicts)}
