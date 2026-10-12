"""Analyzer registry and the static analyzer nodes"""

from __future__ import annotations

from collections.abc import Callable

from skillguard.nodes.analyzers import (
    static_patterns_anti_refusal,
    static_patterns_data_exfiltration,
    static_patterns_privilege_escalation,
    static_patterns_prompt_injection,
    static_patterns_supply_chain,
    static_patterns_trigger_abuse,
)
from skillguard.nodes.analyzers.behavioral_ast import behavioral_ast
from skillguard.nodes.analyzers.static_runner import run_rules
from skillguard.state import ScanState

#: Signature every analyzer node must satisfy.
AnalyzerFn = Callable[[ScanState], dict[str, object]]

#: Importing these modules populated the rule registry.
_CATEGORY_MODULES = (
    static_patterns_prompt_injection,
    static_patterns_anti_refusal,
    static_patterns_data_exfiltration,
    static_patterns_privilege_escalation,
    static_patterns_supply_chain,
    static_patterns_trigger_abuse,
)


def _category_node(category: str) -> AnalyzerFn:
    """Build the analyzer node that runs one rule category"""

    def run(state: ScanState) -> dict[str, object]:
        context = state.get("context")
        if context is None:
            return {"findings": []}
        return {"findings": run_rules(context, category)}

    return run


#: One parallel analyzer per category, plus the structural AST analyzer.
ANALYZER_NODES: dict[str, AnalyzerFn] = {
    **{module.NODE_NAME: _category_node(module.CATEGORY) for module in _CATEGORY_MODULES},
    "behavioral_ast": behavioral_ast,
}
