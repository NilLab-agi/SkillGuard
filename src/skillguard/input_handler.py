"""Resolve a user supplied reference into a local skill directory"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path

from skillguard.constants import (
    GIT_CLONE_TIMEOUT_SECONDS,
    MAX_INPUT_BYTES,
    MAX_ZIP_MEMBERS,
)

# Schemes we treat as URLs rather than local paths.
_URL_PREFIXES: tuple[str, ...] = ("http://", "https://", "git://", "ssh://", "git@", "file://")

# Documented extensions that mean "scan the folder this file lives in".
_DOCUMENT_SUFFIXES: frozenset[str] = frozenset({".md", ".markdown"})

# Do not let git prompt for credentials, and ignore machine-wide config.
_GIT_ENV: dict[str, str] = {
    **os.environ,
    "GIT_TERMINAL_PROMPT": "0",
    "GIT_ASKPASS": "echo",
    "GIT_CONFIG_NOSYSTEM": "1",
}


@dataclass(frozen=True, slots=True)
class ResolvedInput:
    """Where the skill lives, and whether we must delete it afterwards"""

    skill_path: Path | None
    cleanup_dir: Path | None
    error: str | None


def is_url(ref: str) -> bool:
    """True when the reference should be fetched rather than opened."""
    return ref.startswith(_URL_PREFIXES)


def resolve(
    ref: str,
    *,
    max_bytes: int = MAX_INPUT_BYTES,
    max_members: int = MAX_ZIP_MEMBERS,
    timeout: float = GIT_CLONE_TIMEOUT_SECONDS,
) -> ResolvedInput:
    """Turn ``ref`` into a local directory, or return why it could not be

    Caps are parameters so tests can exercise the limits without huge files
    """
    if is_url(ref):
        return _resolve_git(ref, max_bytes=max_bytes, timeout=timeout)

    path = Path(ref).expanduser()
    if path.is_dir():
        return ResolvedInput(path.resolve(), None, None)
    if path.is_file():
        return _resolve_file(path, max_bytes=max_bytes, max_members=max_members)
    return ResolvedInput(None, None, f"path does not exist: {ref}")


def _resolve_file(path: Path, *, max_bytes: int, max_members: int) -> ResolvedInput:
    if path.suffix.lower() in _DOCUMENT_SUFFIXES:
        # A standalone SKILL.md is scanned as part of the folder it sits in
        return ResolvedInput(path.resolve().parent, None, None)
    if path.suffix.lower() == ".zip":
        return _resolve_zip(path, max_bytes=max_bytes, max_members=max_members)
    return ResolvedInput(None, None, f"unsupported input file: {path}")


def is_safe_member(name: str) -> bool:
    """True when a zip entry cannot escape the extraction directory.

    Rejects absolute paths, Windows drive letters, and any ``..`` component.
    """
    if not name:
        return False
    normalised = name.replace("\\", "/")
    if normalised.startswith("/"):
        return False
    if len(normalised) > 1 and normalised[1] == ":":
        return False
    return ".." not in Path(normalised).parts


def _validate_members(
    members: list[zipfile.ZipInfo], *, max_bytes: int, max_members: int
) -> str | None:
    """Return why an archive must be rejected, or None when it is acceptable

    Runs over *every* member before anything is extracted, so a rejected
    archive never writes a single byte to disk
    """
    if len(members) > max_members:
        return f"{len(members)} entries exceeds the {max_members} entry limit"

    total = 0
    for member in members:
        if not is_safe_member(member.filename):
            return f"unsafe path in archive: {member.filename!r}"
        total += member.file_size
        if total > max_bytes:
            return f"uncompressed size exceeds {max_bytes} bytes"
    return None


def _resolve_zip(ref_path: Path, *, max_bytes: int, max_members: int) -> ResolvedInput:
    if not zipfile.is_zipfile(ref_path):
        return ResolvedInput(None, None, f"not a valid zip archive: {ref_path}")

    temp_dir = Path(tempfile.mkdtemp(prefix="skillguard-zip-"))
    try:
        with zipfile.ZipFile(ref_path) as archive:
            problem = _validate_members(
                archive.infolist(), max_bytes=max_bytes, max_members=max_members
            )
            if problem is not None:
                shutil.rmtree(temp_dir, ignore_errors=True)
                return ResolvedInput(None, None, f"rejected archive {ref_path}: {problem}")
            archive.extractall(temp_dir)
    except (zipfile.BadZipFile, OSError) as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return ResolvedInput(None, None, f"failed to read archive {ref_path}: {exc}")

    return ResolvedInput(_content_root(temp_dir), temp_dir, None)


def _content_root(directory: Path) -> Path:
    """Descend through a single wrapper folder, which most archives have"""
    entries = list(directory.iterdir())
    while len(entries) == 1 and entries[0].is_dir():
        directory = entries[0]
        entries = list(directory.iterdir())
    return directory


def _resolve_git(ref: str, *, max_bytes: int, timeout: float) -> ResolvedInput:
    if shutil.which("git") is None:
        return ResolvedInput(None, None, "git is not installed")

    temp_dir = Path(tempfile.mkdtemp(prefix="skillguard-git-"))
    repo = temp_dir / "repo"
    command = [
        "git",
        "clone",
        "--depth",
        "1",
        "--single-branch",
        "--no-tags",
        ref,
        str(repo),
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=_GIT_ENV,
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return ResolvedInput(None, None, f"git clone timed out after {timeout:.0f}s")
    except OSError as exc:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return ResolvedInput(None, None, f"git clone failed: {exc}")

    if completed.returncode != 0:
        shutil.rmtree(temp_dir, ignore_errors=True)
        lines = (completed.stderr or completed.stdout).strip().splitlines()
        detail = lines[-1] if lines else "unknown error"
        return ResolvedInput(None, None, f"git clone failed: {detail}")

    size = _directory_size(repo)
    if size > max_bytes:
        shutil.rmtree(temp_dir, ignore_errors=True)
        return ResolvedInput(None, None, f"repository is larger than {max_bytes} bytes")

    return ResolvedInput(repo, temp_dir, None)


def _directory_size(root: Path) -> int:
    total = 0
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in filenames:
            try:
                total += (Path(dirpath) / name).stat().st_size
            except OSError:
                continue
    return total
