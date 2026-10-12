"""Find and normalize MCP server configurations inside a skill"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from skillguard.constants import SKILL_MANIFEST_NAME
from skillguard.models import ScanContext
from skillguard.nodes.analyzers.common import component_types

# File names that always mean "this file is an MCP config"
MCP_CONFIG_NAMES: frozenset[str] = frozenset({".mcp.json", "mcp.json", "mcp_config.json"})

# Mapping keys that hold a server-name -> server-definition mapping
_MCP_KEYS: tuple[str, ...] = ("mcpServers", "mcp_servers", "mcp", "servers")

# Keys that declare what a server is allowed to do
_DECLARATION_KEYS: tuple[str, ...] = (
    "permissions",
    "capabilities",
    "scopes",
    "allowedTools",
    "allowed_tools",
)

# Keywords used for the declared vs implied comparison (LP1)
CAPABILITY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "http": ("http", "https", "fetch", "url", "network", "webhook"),
    "fs": ("file", "filesystem", "directory", "read_", "write_"),
    "exec": ("exec", "spawn", "subprocess"),
    "shell": ("shell", "bash", "terminal"),
}


@dataclass(frozen=True, slots=True)
class McpTool:
    """One tool a server exposes. Its description is read by the model."""

    server: str
    name: str
    description: str
    parameter_descriptions: tuple[str, ...]
    source: str
    line: int


@dataclass(frozen=True, slots=True)
class McpServer:
    """A normalized MCP server declaration"""

    name: str
    source: str
    line: int
    command: str
    declared: frozenset[str]
    declared_raw: tuple[str, ...]
    has_declaration: bool
    tools: tuple[McpTool, ...]

    @property
    def searchable_text(self) -> str:
        """Everything about this server that a model would read"""
        parts = [self.name, self.command]
        for tool in self.tools:
            parts.extend((tool.name, tool.description, *tool.parameter_descriptions))
        return " ".join(parts)


def _as_dict(value: object) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _line_of(text: str, *needles: str) -> int:
    """1 based line of the first needle found (1 when none is present)"""
    for needle in needles:
        index = text.find(needle)
        if index >= 0:
            return text.count("\n", 0, index) + 1
    return 1


def normalize_capability(value: str) -> str | None:
    """Map one declared permission string to a capability name, if it names one"""
    lowered = value.strip().lower()
    if lowered in CAPABILITY_KEYWORDS:
        return lowered
    for capability, words in CAPABILITY_KEYWORDS.items():
        if any(word in lowered for word in words):
            return capability
    return None


def infer_capabilities(text: str) -> frozenset[str]:
    """Guess which capabilities a server's own text implies"""
    lowered = text.lower()
    return frozenset(
        capability
        for capability, words in CAPABILITY_KEYWORDS.items()
        if any(word in lowered for word in words)
    )


def _declared_values(server: dict[str, Any]) -> tuple[tuple[str, ...], bool]:
    values: list[str] = []
    has_declaration = False
    for key in _DECLARATION_KEYS:
        raw = server.get(key)
        if raw is None:
            continue
        has_declaration = True
        if isinstance(raw, str):
            values.append(raw)
        elif isinstance(raw, list):
            values.extend(item for item in raw if isinstance(item, str))
    return tuple(values), has_declaration


def _parameter_descriptions(schema: object) -> tuple[str, ...]:
    properties = _as_dict(_as_dict(schema).get("properties"))
    return tuple(
        spec["description"]
        for spec in properties.values()
        if isinstance(spec, dict) and isinstance(spec.get("description"), str)
    )


def _tools_for(
    server_name: str, server: dict[str, Any], source: str, text: str
) -> tuple[McpTool, ...]:
    raw_tools = server.get("tools")
    if not isinstance(raw_tools, list):
        return ()
    tools: list[McpTool] = []
    for entry in raw_tools:
        tool = _as_dict(entry)
        name = tool.get("name")
        description = tool.get("description")
        resolved = name if isinstance(name, str) else ""
        tools.append(
            McpTool(
                server=server_name,
                name=resolved,
                description=description if isinstance(description, str) else "",
                parameter_descriptions=_parameter_descriptions(tool.get("inputSchema")),
                source=source,
                line=_line_of(text, f'"{resolved}"', resolved) if resolved else 1,
            )
        )
    return tuple(tools)


def _build_server(name: str, definition: object, source: str, text: str) -> McpServer:
    server = _as_dict(definition)
    declared_raw, has_declaration = _declared_values(server)
    declared = frozenset(
        capability
        for capability in (normalize_capability(item) for item in declared_raw)
        if capability is not None
    )

    command = server.get("command")
    parts = [command] if isinstance(command, str) else []
    args = server.get("args")
    if isinstance(args, list):
        parts.extend(item for item in args if isinstance(item, str))

    return McpServer(
        name=name,
        source=source,
        line=_line_of(text, f'"{name}"', f"{name}:"),
        command=" ".join(parts).strip(),
        declared=declared,
        declared_raw=declared_raw,
        has_declaration=has_declaration,
        tools=_tools_for(name, server, source, text),
    )


def _server_mapping(parsed: dict[str, Any]) -> dict[str, Any]:
    for key in _MCP_KEYS:
        value = parsed.get(key)
        if isinstance(value, dict):
            return {
                name: definition
                for name, definition in value.items()
                if isinstance(definition, dict)
            }
    return {}


def _config_mappings(context: ScanContext) -> list[tuple[str, dict[str, Any], str]]:
    """Return (source, server mapping, full text) for every MCP config found."""
    found: list[tuple[str, dict[str, Any], str]] = []
    types = component_types(context)

    for path, text in context.file_cache.items():
        kind = types.get(path, "other")
        if kind not in {"json", "yaml"}:
            continue
        try:
            parsed: object = json.loads(text) if kind == "json" else yaml.safe_load(text)
        except (json.JSONDecodeError, yaml.YAMLError):
            continue
        parsed_dict = _as_dict(parsed)
        mapping = _server_mapping(parsed_dict)
        if not mapping and Path(path).name in MCP_CONFIG_NAMES:
            # A config file whose root IS the server mapping.
            mapping = {key: value for key, value in parsed_dict.items() if isinstance(value, dict)}
        if mapping:
            found.append((path, mapping, text))

    manifest_mapping = _server_mapping(context.manifest)
    if manifest_mapping:
        manifest_path = next(
            (path for path in context.file_cache if Path(path).name == SKILL_MANIFEST_NAME),
            SKILL_MANIFEST_NAME,
        )
        found.append((manifest_path, manifest_mapping, context.file_cache.get(manifest_path, "")))

    return found


def load_mcp_servers(context: ScanContext) -> tuple[McpServer, ...]:
    """Return every MCP server declared by the skill, normalized."""
    servers: list[McpServer] = []
    for source, mapping, text in _config_mappings(context):
        for name, definition in mapping.items():
            servers.append(_build_server(name, definition, source, text))
    return tuple(servers)
