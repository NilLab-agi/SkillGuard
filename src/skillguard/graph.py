"""Build the LangGraph scan pipeline"""

from __future__ import annotations

from collections.abc import Mapping

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from skillguard.nodes.analyzers import ANALYZER_NODES, AnalyzerFn
from skillguard.nodes.build_context import build_context
from skillguard.nodes.deduplicate import deduplicate
from skillguard.nodes.meta_analyzer import meta_analyzer
from skillguard.nodes.report import report_node
from skillguard.nodes.resolve_input import resolve_input
from skillguard.nodes.score import score_node
from skillguard.state import ScanState


def should_run_llm(state: ScanState) -> str:
    """Conditional edge chooser: run the LLM stage only when asked"""
    return "llm" if state.get("use_llm") else "skip"


# what build_graph returns: state in, state out, no runtime context type
ScanGraph = CompiledStateGraph[ScanState, None, ScanState, ScanState]


def build_graph(
    *,
    analyzers: Mapping[str, AnalyzerFn] | None = None,
    checkpointer: BaseCheckpointSaver | None = None,
) -> ScanGraph:
    """Compile the graph.

    ``analyzers`` swaps the registry (tests do). ``checkpointer`` enables
    persistence: with one, a scan can be inspected or resumed by thread id.
    """
    registry = ANALYZER_NODES if analyzers is None else analyzers
    builder = StateGraph[ScanState, None, ScanState, ScanState](ScanState)

    builder.add_node("resolve_input", resolve_input)
    builder.add_node("build_context", build_context)
    for name, fn in registry.items():
        builder.add_node(name, fn)  # type: ignore[arg-type]  # langgraph node union: mypy cannot infer NodeInputT
    builder.add_node("deduplicate", deduplicate)
    builder.add_node("meta_analyzer", meta_analyzer)
    builder.add_node("score", score_node)
    builder.add_node("report", report_node)

    builder.add_edge(START, "resolve_input")
    builder.add_edge("resolve_input", "build_context")

    # fan-out: every analyzer sees the same context
    # fan-in: every analyzer must finish before deduplicate runs
    for name in registry:
        builder.add_edge("build_context", name)
        builder.add_edge(name, "deduplicate")

    # Conditional edge: --no-llm skips the LLM stage entirely.
    builder.add_conditional_edges(
        "deduplicate",
        should_run_llm,
        {"llm": "meta_analyzer", "skip": "score"},
    )
    builder.add_edge("meta_analyzer", "score")
    builder.add_edge("score", "report")
    builder.add_edge("report", END)

    return builder.compile(checkpointer=checkpointer)


# Module level instance so `langgraph dev` and the CLI share one graph.
graph = build_graph()
