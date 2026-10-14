"""Turn a skill directory into a ScanContext.

Discovery is deliberately boring and deterministic:
- walk in sorted order so reports are reproducible,
- never descend into vendor directories or follow symlinks,
- read each file once, then serve analyzers from the in-memory cache.
"""

from __future__ import annotations

import os
from pathlib import Path

import yaml

from skillguard.constants import (
    BYTECODE_DIRS,
    EXECUTABLE_EXTENSIONS,
    IGNORE_DIRS,
    SHIPPED_BYTECODE_REASON,
    SKILL_MANIFEST_NAME,
)
from skillguard.models import Component, ScanContext
from skillguard.readers import read_file

_TYPE_BY_SUFFIX: dict[str, str] = {
    ".py": "python",
    ".md": "markdown",
    ".sh": "shell",
    ".bash": "shell",
    ".zsh": "shell",
    ".js": "javascript",
    ".mjs": "javascript",
    ".ts": "typescript",
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".txt": "text",
    ".cfg": "text",
    ".ini": "text",
}


def classify(path: Path) -> str:
    """Return the component type for a path"""
    if path.name.startswith("requirements") and path.suffix == ".txt":
        return "requirements"
    return _TYPE_BY_SUFFIX.get(path.suffix.lower(), "other")


def parse_front_matter(text: str) -> dict[str, object]:
    """Parse the YAML front-matter of a SKILL.md-style document

    Returns {} when there is none, or when it is unparseable. ``safe_load`` is
    mandatory: ``yaml.load`` can build arbitrary Python objects, i.e. run code
    from the untrusted skill we are supposed to be vetting.
    """
    if not text.startswith("---"):
        return {}
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}
    try:
        data = yaml.safe_load(parts[1])
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def discover(skill_path: str, *, max_files: int, max_file_bytes: int) -> ScanContext:
    """Walk ``skill_path`` and build the context analyzers read from."""
    root = Path(skill_path).resolve()
    components: list[Component] = []
    file_cache: dict[str, str] = {}
    skipped: list[tuple[str, str]] = []
    manifest: dict[str, object] = {}
    has_executable = False

    for current_dir, dirnames, filenames in os.walk(root):
        # Record bytecode directories before pruning: shipping .pyc is itself
        # a finding, but we never want to read the bytecode.
        for name in sorted(dirnames):
            if name in BYTECODE_DIRS:
                relative = (Path(current_dir) / name).relative_to(root).as_posix()
                skipped.append((f"{relative}/", SHIPPED_BYTECODE_REASON))

        # Prune in place: os.walk never descends into these at all.
        dirnames[:] = sorted(name for name in dirnames if name not in IGNORE_DIRS)

        for filename in sorted(filenames):
            path = Path(current_dir) / filename
            rel = path.relative_to(root).as_posix()

            # A symlink can point outside the skill tree (e.g. /etc/passwd).
            if path.is_symlink():
                skipped.append((rel, "symlink"))
                continue

            if len(components) >= max_files:
                skipped.append((rel, f"max_files exceeded: {max_files}"))
                continue

            executable = path.suffix.lower() in EXECUTABLE_EXTENSIONS
            has_executable = has_executable or executable
            result = read_file(path, max_bytes=max_file_bytes)

            components.append(
                Component(
                    path=rel,
                    type=classify(path),
                    lines=result.lines,
                    executable=executable,
                    size_bytes=result.size_bytes,
                )
            )

            if result.content is None:
                # Recorded as a component (we saw it) but not analyzed.
                skipped.append((rel, result.skip_reason or "skipped"))
                continue

            file_cache[rel] = result.content
            if filename == SKILL_MANIFEST_NAME:
                manifest = parse_front_matter(result.content)

    return ScanContext(
        skill_path=str(root),
        components=components,
        file_cache=file_cache,
        manifest=manifest,
        has_executable_scripts=has_executable,
        skipped=skipped,
    )
