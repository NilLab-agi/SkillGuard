"""The graph's shared state.

LangGraph runs nodes as plain functions over one shared dict: each node receives
the whole state and returns *only the keys it changed*. LangGraph then merges
those partial results. For most keys the merge overwrites; for keys annotated
with a *reducer*, it combines instead.
"""

from __future__ import annotations

import operator
from typing import Annotated, TypedDict

from skillguard.models import Finding, Report, RiskAssessment, ScanContext


class ScanState(TypedDict, total=False):
    """Everything that flows between nodes.

    ``total=False`` makes every key optional, because a node returns only the
    part of the state it changed.
    """

    # input: set by the CLI before the graph is invoked
    input_ref: str
    output_format: str
    use_llm: bool
    use_osv: bool
    verbose: bool

    # resolved context
    skill_path: str
    cleanup_dir: str | None  # temp dir to delete afterwards (Phase 9)
    context: ScanContext

    # findings
    findings: Annotated[list[Finding], operator.add]
    effective_findings: list[Finding]  # no reducer: deduplicate is sole writer

    # results
    risk: RiskAssessment
    report: Report
    errors: Annotated[list[str], operator.add]
