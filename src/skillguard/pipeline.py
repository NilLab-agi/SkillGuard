"""Thin wrapper around the compiled graph.

The CLI never imports LangGraph: it sees node updates and a final Report
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, cast

from skillguard.graph import graph
from skillguard.state import ScanState

Update = tuple[str, dict[str, Any]]


def initial_state(
    input_ref: str,
    *,
    output_format: str = "terminal",
    use_llm: bool = False,
    use_osv: bool = False,
    verbose: bool = False,
) -> ScanState:
    """Seed the state. Reducer channels must start as lists, not be missing."""
    return ScanState(
        input_ref=input_ref,
        output_format=output_format,
        use_llm=use_llm,
        use_osv=use_osv,
        verbose=verbose,
        findings=[],
        errors=[],
    )


def stream_scan(state: ScanState) -> Iterator[Update]:
    """Yield (node_name, partial update) as each node completes."""
    for chunk in graph.stream(state, stream_mode="updates"):
        yield from chunk.items()


def run_scan(state: ScanState) -> ScanState:
    """Run to completion and return the fully merged state."""
    return cast(ScanState, graph.invoke(state))
