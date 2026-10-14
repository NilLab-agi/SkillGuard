"""Every rule the scanner can emit, as data.

Regex rules live in ``REGISTRY`` (registered at import time by the category
modules). Structural rules — AST, MCP, dependency — are declared here, because
they are emitted by node code rather than by a regex.

``docs/RULES.md`` is generated from this module by a test, so the docs cannot
drift from the code. Regenerate with:

    uv run python -m skillguard.rule_catalog > docs/RULES.md
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from skillguard.models import Severity
from skillguard.nodes.analyzers.pattern_defaults import REGISTRY


@dataclass(frozen=True, slots=True)
class RuleInfo:
    """One documented rule."""

    id: str
    category: str
    severity: Severity
    summary: str
    remediation: str


#: Rules emitted by node code instead of the regex registry.
NODE_RULES: tuple[RuleInfo, ...] = (
    # --- structural Python analysis (behavioral_ast.py) ---
    RuleInfo(
        "AST1",
        "dangerous_execution",
        Severity.CRITICAL,
        "exec() executes arbitrary code",
        "Remove exec(); it runs attacker-controlled code.",
    ),
    RuleInfo(
        "AST2",
        "dangerous_execution",
        Severity.HIGH,
        "eval() evaluates arbitrary expressions",
        "Replace eval() with a safe parser.",
    ),
    RuleInfo(
        "AST3",
        "dangerous_execution",
        Severity.HIGH,
        "Dynamic import of a computed module name",
        "Use a static import so dependencies stay visible.",
    ),
    RuleInfo(
        "AST4",
        "dangerous_execution",
        Severity.HIGH,
        "Subprocess execution",
        "Do not spawn processes from a skill.",
    ),
    RuleInfo(
        "TM1",
        "tool_misuse",
        Severity.HIGH,
        "Shell execution with shell=True",
        "Pass an argument list instead of shell=True.",
    ),
    RuleInfo(
        "AST5",
        "dangerous_execution",
        Severity.HIGH,
        "Operating-system command execution",
        "Do not run shell commands from a skill.",
    ),
    RuleInfo(
        "AST6",
        "dangerous_execution",
        Severity.MEDIUM,
        "compile() builds a code object",
        "Avoid compiling untrusted source.",
    ),
    RuleInfo(
        "AST7",
        "dangerous_execution",
        Severity.MEDIUM,
        "Dynamic attribute access hides the real call",
        "Reference the attribute directly so it can be reviewed.",
    ),
    RuleInfo(
        "AST8",
        "dangerous_execution",
        Severity.CRITICAL,
        "Execution of a decoded or remote payload",
        "Remove encoded execution; it hides what actually runs.",
    ),
    # --- MCP least privilege (mcp_least_privilege.py) ---
    RuleInfo(
        "LP1",
        "mcp_least_privilege",
        Severity.MEDIUM,
        "Server implies a capability it does not declare",
        "Declare every capability the server's tools actually need.",
    ),
    RuleInfo(
        "LP2",
        "mcp_least_privilege",
        Severity.HIGH,
        "Server requests a wildcard permission",
        "Replace wildcard permissions with the narrowest capability set.",
    ),
    RuleInfo(
        "LP3",
        "mcp_least_privilege",
        Severity.MEDIUM,
        "Server declares no capabilities",
        "Declare an explicit, minimal capability list for the server.",
    ),
    # --- MCP tool poisoning (mcp_tool_poisoning.py) ---
    RuleInfo(
        "TP1",
        "mcp_tool_poisoning",
        Severity.HIGH,
        "Hidden content in a tool description",
        "Remove hidden characters; a description must read as it appears.",
    ),
    RuleInfo(
        "TP2",
        "mcp_tool_poisoning",
        Severity.HIGH,
        "Unicode deception in a tool description",
        "Use plain text with no lookalike or direction-control characters.",
    ),
    RuleInfo(
        "TP3",
        "mcp_tool_poisoning",
        Severity.HIGH,
        "Instruction-like text in a parameter description",
        "Parameter descriptions describe the parameter, not the model.",
    ),
    # --- dependencies (supply_chain_dependencies.py) ---
    RuleInfo(
        "SC1",
        "supply_chain",
        Severity.LOW,
        "Dependency has no version constraint",
        "Pin the dependency to an exact version for reproducible installs.",
    ),
    RuleInfo(
        "SC6",
        "supply_chain",
        Severity.HIGH,
        "Dependency name looks like a popular package",
        "Check the spelling; install the package you actually meant.",
    ),
    RuleInfo(
        "SC10",
        "supply_chain",
        Severity.HIGH,
        "Dependency source redirected",
        "Install from the default package index unless you control the source.",
    ),
    # --- file shapes (supply_chain_files.py) ---
    RuleInfo(
        "SC8",
        "supply_chain",
        Severity.HIGH,
        "Compiled Python bytecode is shipped in the skill",
        "Remove __pycache__; bytecode is unreadable and can hide code.",
    ),
    RuleInfo(
        "SC9",
        "supply_chain",
        Severity.HIGH,
        "Executable disguised as a document",
        "Rename the file so its extension matches what it does.",
    ),
    # --- live vulnerability lookup (supply_chain_osv.py) ---
    RuleInfo(
        "SC4",
        "supply_chain",
        Severity.HIGH,
        "Dependency version has known vulnerabilities",
        "Upgrade to a patched version of this dependency.",
    ),
)


def _sort_key(rule: RuleInfo) -> tuple[str, str, int]:
    """Natural order: SC2 before SC10, not after it."""
    match = re.match(r"([A-Z]+)(\d+)", rule.id)
    prefix, number = (match.group(1), int(match.group(2))) if match else (rule.id, 0)
    return (rule.category, prefix, number)


def all_rules() -> tuple[RuleInfo, ...]:
    """Every rule, regex and structural, ordered by category then id."""
    regex = tuple(
        RuleInfo(rule.id, rule.category, rule.severity, rule.message, rule.remediation)
        for rule in REGISTRY
    )
    return tuple(sorted(regex + NODE_RULES, key=_sort_key))


def render_rules_markdown() -> str:
    """Render the rule reference. Used by the docs drift test."""
    rules = all_rules()
    categories = sorted({rule.category for rule in rules})

    lines = [
        "# SkillGuard rule reference",
        "",
        f"{len(rules)} rules across {len(categories)} categories.",
        "",
        "> Generated from the rule catalog. Do not edit by hand.",
        "> Regenerate with: `uv run python -m skillguard.rule_catalog > docs/RULES.md`",
        "",
        "| Category | Rules |",
        "| --- | --- |",
    ]
    for category in categories:
        ids = ", ".join(rule.id for rule in rules if rule.category == category)
        lines.append(f"| `{category}` | {ids} |")

    lines.append("")
    for category in categories:
        lines += [
            f"## {category}",
            "",
            "| ID | Severity | What it detects | Remediation |",
            "| --- | --- | --- | --- |",
        ]
        for rule in rules:
            if rule.category != category:
                continue
            lines.append(
                f"| `{rule.id}` | {rule.severity.value} | {rule.summary} | {rule.remediation} |"
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


if __name__ == "__main__":  # pragma: no cover - generator entry point
    print(render_rules_markdown(), end="")
