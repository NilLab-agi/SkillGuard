"""resolving directories, files, archives, and git URLs"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

import pytest

from skillguard.input_handler import is_safe_member, is_url, resolve

GIT_AVAILABLE = shutil.which("git") is not None


def _write_zip(path: Path, entries: dict[str, str]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, content in entries.items():
            archive.writestr(name, content)


def _skill_dir(root: Path, name: str = "skill") -> Path:
    directory = root / name
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "SKILL.md").write_text("---\nname: demo\n---\n", encoding="utf-8")
    return directory


def _cleanup(resolved: object) -> None:
    cleanup = getattr(resolved, "cleanup_dir", None)
    if cleanup:
        shutil.rmtree(cleanup, ignore_errors=True)


# ------------------------------------------------------------------ directories


def test_resolves_a_directory(tmp_path: Path) -> None:
    directory = _skill_dir(tmp_path)

    resolved = resolve(str(directory))

    assert resolved.error is None
    assert resolved.skill_path == directory.resolve()
    assert resolved.cleanup_dir is None


def test_resolves_a_markdown_file_to_its_parent(tmp_path: Path) -> None:
    directory = _skill_dir(tmp_path)

    resolved = resolve(str(directory / "SKILL.md"))

    assert resolved.error is None
    assert resolved.skill_path == directory.resolve()


def test_rejects_an_unsupported_file(tmp_path: Path) -> None:
    target = tmp_path / "notes.txt"
    target.write_text("hello", encoding="utf-8")

    resolved = resolve(str(target))

    assert resolved.error is not None
    assert "unsupported" in resolved.error


def test_rejects_a_missing_path(tmp_path: Path) -> None:
    assert resolve(str(tmp_path / "nope")).error is not None


# ------------------------------------------------------------------------- zip


def test_extracts_a_zip(tmp_path: Path) -> None:
    archive = tmp_path / "skill.zip"
    _write_zip(
        archive,
        {"SKILL.md": "---\nname: demo\n---\n", "scripts/run.py": "print(1)\n"},
    )

    resolved = resolve(str(archive))
    try:
        assert resolved.error is None
        assert resolved.skill_path is not None
        assert (resolved.skill_path / "SKILL.md").is_file()
        assert (resolved.skill_path / "scripts" / "run.py").is_file()
    finally:
        _cleanup(resolved)


def test_descends_a_single_wrapper_directory(tmp_path: Path) -> None:
    archive = tmp_path / "wrapped.zip"
    _write_zip(archive, {"my-skill-main/SKILL.md": "---\nname: demo\n---\n"})

    resolved = resolve(str(archive))
    try:
        assert resolved.skill_path is not None
        assert resolved.skill_path.name == "my-skill-main"
    finally:
        _cleanup(resolved)


def test_rejects_path_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "evil.zip"
    _write_zip(archive, {"../escape.txt": "pwned", "SKILL.md": "x"})

    resolved = resolve(str(archive))

    assert resolved.error is not None
    assert "unsafe path" in resolved.error


def test_rejects_an_absolute_path(tmp_path: Path) -> None:
    archive = tmp_path / "absolute.zip"
    _write_zip(archive, {"/etc/passwd": "x"})

    assert resolve(str(archive)).error is not None


def test_rejected_archive_writes_nothing(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    archive = workspace / "evil.zip"
    _write_zip(archive, {"../escape.txt": "pwned"})
    before = set(Path(tempfile.gettempdir()).glob("skillguard-zip-*"))

    resolved = resolve(str(archive))

    assert resolved.error is not None
    assert set(Path(tempfile.gettempdir()).glob("skillguard-zip-*")) == before
    assert not (workspace.parent / "escape.txt").exists()


def test_rejects_too_many_members(tmp_path: Path) -> None:
    archive = tmp_path / "many.zip"
    _write_zip(archive, {f"file{i}.txt": "x" for i in range(5)})

    resolved = resolve(str(archive), max_members=2)

    assert resolved.error is not None
    assert "entry limit" in resolved.error


def test_rejects_an_oversized_archive(tmp_path: Path) -> None:
    archive = tmp_path / "big.zip"
    _write_zip(archive, {"SKILL.md": "x" * 500})

    resolved = resolve(str(archive), max_bytes=100)

    assert resolved.error is not None
    assert "uncompressed size" in resolved.error


def test_rejects_a_file_that_is_not_a_zip(tmp_path: Path) -> None:
    fake = tmp_path / "fake.zip"
    fake.write_text("not a zip", encoding="utf-8")

    resolved = resolve(str(fake))

    assert resolved.error is not None
    assert "not a valid zip" in resolved.error


# ------------------------------------------------------------------ git / urls


@pytest.mark.parametrize(
    "ref", ["https://github.com/x/y", "git@github.com:x/y.git", "file:///tmp/x"]
)
def test_url_detection(ref: str) -> None:
    assert is_url(ref)


def test_local_paths_are_not_urls() -> None:
    assert not is_url("./some-skill")
    assert not is_url("/abs/path")


@pytest.mark.skipif(not GIT_AVAILABLE, reason="git is not installed")
def test_git_failure_is_reported_not_raised(tmp_path: Path) -> None:
    resolved = resolve(f"file://{tmp_path}/not-a-repo")

    assert resolved.error is not None
    assert "git clone failed" in resolved.error


@pytest.mark.skipif(not GIT_AVAILABLE, reason="git is not installed")
def test_clones_a_local_repository(tmp_path: Path) -> None:
    source = _skill_dir(tmp_path / "origin", "repo")
    for args in (("init", "-b", "main"), ("add", "."), ("commit", "-m", "init")):
        subprocess.run(
            ["git", "-c", "user.name=Test", "-c", "user.email=test@example.com", *args],
            cwd=source,
            check=True,
            capture_output=True,
        )

    resolved = resolve(f"file://{source}")
    try:
        assert resolved.error is None
        assert resolved.skill_path is not None
        assert (resolved.skill_path / "SKILL.md").is_file()
        assert resolved.cleanup_dir is not None
    finally:
        _cleanup(resolved)


def test_safe_member_rules() -> None:
    assert is_safe_member("SKILL.md")
    assert is_safe_member("scripts/run.py")
    assert not is_safe_member("../escape.txt")
    assert not is_safe_member("a/../../b.txt")
    assert not is_safe_member("/etc/passwd")
    assert not is_safe_member("C:/windows/system32")
    assert not is_safe_member("")
