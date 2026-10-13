"""Resolve the user's input reference into a local skill directory"""

from __future__ import annotations

from skillguard.input_handler import resolve
from skillguard.state import ScanState


def resolve_input(state: ScanState) -> dict[str, object]:
    """Resolve dir/file/zip/git input; record an error instead of raising"""
    resolved = resolve(state.get("input_ref", ""))
    if resolved.error is not None or resolved.skill_path is None:
        return {"errors": [f"resolve_input: {resolved.error or 'no skill path'}"]}

    return {
        "skill_path": str(resolved.skill_path),
        "cleanup_dir": str(resolved.cleanup_dir) if resolved.cleanup_dir else None,
    }
