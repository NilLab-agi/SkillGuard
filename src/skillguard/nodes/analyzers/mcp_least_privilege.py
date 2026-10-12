"""MCP least-privilege analyzer.

Compares what a server *declares* it may do with what its own text implies
"""

from __future__ import annotations

from skillguard.models import Finding, Location, Severity
from skillguard.nodes.analyzers.mcp_config import (
    McpServer,
    infer_capabilities,
    load_mcp_servers,
)
from skillguard.state import ScanState

_CATEGORY = "mcp_least_privilege"

# Permission strings that grant everything.
_WILDCARDS: frozenset[str] = frozenset({"*", "**", "all", "full", "any", "everything"})


def _finding(
    rule_id: str,
    severity: Severity,
    message: str,
    remediation: str,
    confidence: float,
    server: McpServer,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        category=_CATEGORY,
        severity=severity,
        message=message,
        location=Location(file=server.source, start_line=server.line),
        confidence=confidence,
        remediation=remediation,
    )


def _wildcards(server: McpServer) -> tuple[str, ...]:
    return tuple(
        value
        for value in server.declared_raw
        if value.strip().lower() in _WILDCARDS or "*" in value
    )


def _server_findings(server: McpServer) -> list[Finding]:
    wildcards = _wildcards(server)

    # A wildcard already grants everything, so "under-declared" cannot apply.
    if wildcards:
        return [
            _finding(
                "LP2",
                Severity.HIGH,
                f"MCP server '{server.name}' requests a wildcard permission ({wildcards[0]})",
                "Replace wildcard permissions with the narrowest capability set.",
                0.9,
                server,
            )
        ]

    if not server.has_declaration:
        return [
            _finding(
                "LP3",
                Severity.MEDIUM,
                f"MCP server '{server.name}' declares no capabilities",
                "Declare an explicit, minimal capability list for the server.",
                0.8,
                server,
            )
        ]

    missing = sorted(infer_capabilities(server.searchable_text) - server.declared)
    if not missing:
        return []

    declared = ", ".join(sorted(server.declared)) or "nothing"
    return [
        _finding(
            "LP1",
            Severity.MEDIUM,
            f"MCP server '{server.name}' implies {', '.join(missing)} but declares only {declared}",
            "Declare every capability the server's tools actually need.",
            0.7,
            server,
        )
    ]


def mcp_least_privilege(state: ScanState) -> dict[str, object]:
    """Analyzer node: declared-vs-implied MCP capabilities."""
    context = state.get("context")
    if context is None:
        return {"findings": []}
    return {
        "findings": [
            finding for server in load_mcp_servers(context) for finding in _server_findings(server)
        ]
    }
