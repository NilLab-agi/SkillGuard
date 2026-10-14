"""SC4: known vulnerabilities in pinned dependencies, via OSV.dev."""

from __future__ import annotations

from skillguard.dependencies import collect_dependencies
from skillguard.models import Finding, Location, Severity
from skillguard.providers.osv import OsvClient
from skillguard.state import ScanState


def supply_chain_osv(state: ScanState) -> dict[str, object]:
    """Analyzer node: live (or fallback) vulnerability lookup.

    Off unless the caller asked for it: this node sends dependency coordinates
    to a third party, so it is opt-in.
    """
    context = state.get("context")
    if context is None or not state.get("use_osv", False):
        return {"findings": []}

    pinned = [d for d in collect_dependencies(context).dependencies if d.version]
    if not pinned:
        return {"findings": []}

    results = OsvClient().query(pinned)
    findings: list[Finding] = []

    # One finding per dependency, listing every advisory. Emitting one finding
    # per advisory would be silently collapsed anyway, because deduplicate keys
    # on (rule, file, line) and all advisories share a line.
    for dependency in pinned:
        vulnerabilities = results.get(f"{dependency.name}=={dependency.version}", [])
        if not vulnerabilities:
            continue
        advisory_ids = ", ".join(sorted({v.vuln_id for v in vulnerabilities}))
        findings.append(
            Finding(
                rule_id="SC4",
                category="supply_chain",
                severity=Severity.HIGH,
                message=(
                    f"{dependency.name}=={dependency.version} has known "
                    f"vulnerabilities ({advisory_ids})"
                ),
                location=Location(file=dependency.source, start_line=dependency.line),
                snippet=f"{dependency.name}=={dependency.version}",
                confidence=0.9,
                remediation="Upgrade to a patched version of this dependency.",
            )
        )

    return {"findings": findings}
