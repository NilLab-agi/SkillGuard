"""Fixed limits and identity for the scanner.

Operational knobs an operator may tune live in `config.Settings`.
These are the numbers that must not change at runtime.
"""

from __future__ import annotations

from importlib.metadata import version

SCANNER_VERSION: str = version("skillguard")

# Largest single source file we will read into memory
MAX_FILE_BYTES_DEFAULT: int = 1_000_000  # 1 MB

# Largest number of files we will walk in one skill
MAX_FILES_DEFAULT: int = 5_000  # 500 files

# Hard ceiling on untrusted input (URL downloads, archives, clones)
MAX_INPUT_BYTES: int = 100 * 1024 * 1024  # 100 MiB

# Hard ceiling on the number of entries in a single zip archive
MAX_ZIP_MEMBERS: int = 10_000

# Longest we will wait for a git clone before giving up
GIT_CLONE_TIMEOUT_SECONDS: float = 60.0

# Directories that never contain skill logic worth scanning
IGNORE_DIRS: frozenset[str] = frozenset(
    {".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache", ".ruff_cache"}
)

# File that identifies a skill and carries its front-matter manifest
SKILL_MANIFEST_NAME: str = "SKILL.md"

# Extensions whose contents can execute; drives the 1.3x risk multiplier
EXECUTABLE_EXTENSIONS: frozenset[str] = frozenset(
    {".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".ps1", ".bat"}
)
