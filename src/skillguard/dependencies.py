"""Parse dependency declarations into structured records.

Three file kinds are understood: ``requirements*.txt``, ``pyproject.toml`` and
``package.json``. Parsing is separated from the rules so the same records feed
the SC1/SC6/SC10 rules *and* the OSV.dev lookup.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from skillguard.models import ScanContext
from skillguard.nodes.analyzers.common import component_types

#: Packages that typosquatters impersonate. Curated, not exhaustive.
POPULAR_PACKAGES: frozenset[str] = frozenset(
    {
        "aiohttp",
        "ansible",
        "attrs",
        "boto3",
        "celery",
        "certifi",
        "charset-normalizer",
        "click",
        "colorama",
        "cryptography",
        "django",
        "docker",
        "fastapi",
        "flake8",
        "flask",
        "grpcio",
        "httpx",
        "idna",
        "jinja2",
        "kubernetes",
        "langchain",
        "lxml",
        "matplotlib",
        "mypy",
        "numpy",
        "openai",
        "packaging",
        "pandas",
        "paramiko",
        "pillow",
        "protobuf",
        "psycopg2",
        "pydantic",
        "pygments",
        "pytest",
        "python-dateutil",
        "pytz",
        "pyyaml",
        "redis",
        "requests",
        "rich",
        "scipy",
        "setuptools",
        "six",
        "sqlalchemy",
        "tensorflow",
        "torch",
        "tqdm",
        "transformers",
        "typing-extensions",
        "urllib3",
        "uvicorn",
        "virtualenv",
        "websockets",
        "wheel",
    }
)

#: name[extras] specifier
_REQUIREMENT_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[(?P<extras>[^\]]*)\])?"
    r"\s*(?P<specifier>.*)$"
)

#: The exact version in an "==" pin.
_EXACT_RE = re.compile(r"==\s*([^,;\s]+)")

#: A bare semver, used for npm's exact pins.
_NPM_EXACT_RE = re.compile(r"\d+(?:\.\d+){0,2}")

#: Index options that mean "install from somewhere else".
_INDEX_OPTIONS: tuple[str, ...] = ("--index-url", "--extra-index-url", "-i ")

#: npm specifiers that mean "any version".
_NPM_ANY: frozenset[str] = frozenset({"", "*", "latest", "x"})


@dataclass(frozen=True, slots=True)
class Dependency:
    """One declared dependency."""

    name: str
    version: str | None  # exact pin only; None for ranges and unpinned
    specifier: str  # the raw constraint; "" means unpinned
    ecosystem: str  # "PyPI" | "npm"
    source: str
    line: int


@dataclass(frozen=True, slots=True)
class DependencySource:
    """A non-default place a dependency would be fetched from."""

    source: str
    line: int
    target: str
    reason: str


@dataclass(frozen=True, slots=True)
class DependencyReport:
    """Everything dependency parsing found in one scan."""

    dependencies: tuple[Dependency, ...]
    redirects: tuple[DependencySource, ...]


def _line_of(text: str, needle: str) -> int:
    index = text.find(needle)
    return text.count("\n", 0, index) + 1 if index >= 0 else 1


def _split_specifier(name: str, specifier: str) -> tuple[str | None, str]:
    """Return (exact version or None, raw specifier)."""
    cleaned = specifier.strip().rstrip(";").strip()
    if not cleaned:
        return None, ""
    match = _EXACT_RE.search(cleaned)
    if match:
        return match.group(1).strip(), cleaned
    return None, cleaned


def parse_requirement(text: str, *, source: str, line: int, ecosystem: str) -> Dependency | None:
    """Parse one requirement string such as ``requests[security]>=2.0``."""
    match = _REQUIREMENT_RE.match(text.strip())
    if match is None:
        return None
    name = match.group("name")
    version, specifier = _split_specifier(name, match.group("specifier") or "")
    return Dependency(
        name=name,
        version=version,
        specifier=specifier,
        ecosystem=ecosystem,
        source=source,
        line=line,
    )


def parse_requirements(text: str, source: str) -> tuple[list[Dependency], list[DependencySource]]:
    """Parse a requirements.txt file."""
    dependencies: list[Dependency] = []
    redirects: list[DependencySource] = []

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        lowered = line.lower()

        if lowered.startswith(_INDEX_OPTIONS):
            redirects.append(DependencySource(source, number, line, "custom package index"))
            continue
        if line.startswith("-"):
            # -e/-r/-c and VCS installs: either local or remote, never the index.
            if "git+" in lowered or lowered.startswith("-e"):
                redirects.append(
                    DependencySource(source, number, line, "direct or editable install")
                )
            continue
        if " @ " in line or "://" in line:
            redirects.append(DependencySource(source, number, line, "direct URL reference"))
            continue

        dependency = parse_requirement(line, source=source, line=number, ecosystem="PyPI")
        if dependency is not None:
            dependencies.append(dependency)

    return dependencies, redirects


def parse_pyproject(text: str, source: str) -> tuple[list[Dependency], list[DependencySource]]:
    """Parse PEP 621 and Poetry dependency tables from pyproject.toml."""
    dependencies: list[Dependency] = []
    redirects: list[DependencySource] = []
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return dependencies, redirects

    project = data.get("project", {})
    groups: list[list[object]] = [project.get("dependencies", [])]
    groups.extend(project.get("optional-dependencies", {}).values())

    for group in groups:
        for entry in group:
            if not isinstance(entry, str):
                continue
            if "://" in entry or " @ " in entry:
                redirects.append(
                    DependencySource(source, _line_of(text, entry), entry, "direct URL reference")
                )
                continue
            dependency = parse_requirement(
                entry, source=source, line=_line_of(text, entry), ecosystem="PyPI"
            )
            if dependency is not None:
                dependencies.append(dependency)

    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, spec in poetry.items():
        if name.lower() == "python":
            continue
        if isinstance(spec, dict):
            # Poetry allows {version = "...", source = "..."} and git/path forms.
            if any(key in spec for key in ("git", "url", "path")):
                redirects.append(
                    DependencySource(
                        source, _line_of(text, name), name, "direct or editable install"
                    )
                )
                continue
            spec = spec.get("version", "")
        version, specifier = _split_specifier(name, str(spec))
        dependencies.append(
            Dependency(
                name=name,
                version=version,
                specifier=specifier,
                ecosystem="PyPI",
                source=source,
                line=_line_of(text, name),
            )
        )

    return dependencies, redirects


def parse_package_json(text: str, source: str) -> tuple[list[Dependency], list[DependencySource]]:
    """Parse npm dependencies from package.json."""
    dependencies: list[Dependency] = []
    redirects: list[DependencySource] = []
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return dependencies, redirects
    if not isinstance(data, dict):
        return dependencies, redirects

    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        entries = data.get(section)
        if not isinstance(entries, dict):
            continue
        for name, spec in entries.items():
            if not isinstance(spec, str):
                continue
            line = _line_of(text, f'"{name}"')
            if spec.startswith(("http:", "https:", "git:", "git+", "file:")):
                redirects.append(
                    DependencySource(source, line, f"{name}@{spec}", "direct URL reference")
                )
                continue
            cleaned = spec.strip()
            exact = cleaned if _NPM_EXACT_RE.fullmatch(cleaned) else None
            specifier = "" if cleaned.lower() in _NPM_ANY else cleaned
            dependencies.append(
                Dependency(
                    name=name,
                    version=exact,
                    specifier=specifier,
                    ecosystem="npm",
                    source=source,
                    line=line,
                )
            )

    return dependencies, redirects


def _edit_distance(left: str, right: str) -> int:
    """Optimal string alignment distance: a transposition costs one edit.

    Transpositions are the commonest typosquat (``reqeusts``), and plain
    Levenshtein scores them as two edits, so they would be missed.
    """
    two_back: list[int] = []
    previous = list(range(len(right) + 1))
    for i, lchar in enumerate(left, start=1):
        current = [i]
        for j, rchar in enumerate(right, start=1):
            cost = 0 if lchar == rchar else 1
            best = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            if i > 1 and j > 1 and lchar == right[j - 2] and left[i - 2] == rchar:
                best = min(best, two_back[j - 2] + 1)
            current.append(best)
        two_back = previous
        previous = current
    return previous[-1]


def typosquat_of(name: str) -> str | None:
    """Return the popular package ``name`` impersonates, or None."""
    candidate = name.lower().replace("_", "-")
    if len(candidate) < 5 or candidate in POPULAR_PACKAGES:
        return None
    for popular in POPULAR_PACKAGES:
        if len(popular) >= 6 and _edit_distance(candidate, popular) == 1:
            return popular
    return None


def collect_dependencies(context: ScanContext) -> DependencyReport:
    """Parse every dependency file in the scan context."""
    dependencies: list[Dependency] = []
    redirects: list[DependencySource] = []
    types = component_types(context)

    for path, text in context.file_cache.items():
        kind = types.get(path, "other")
        name = Path(path).name

        if kind == "requirements":
            found, redirected = parse_requirements(text, path)
        elif kind == "toml" and name == "pyproject.toml":
            found, redirected = parse_pyproject(text, path)
        elif kind == "json" and name == "package.json":
            found, redirected = parse_package_json(text, path)
        else:
            continue

        dependencies.extend(found)
        redirects.extend(redirected)

    return DependencyReport(tuple(dependencies), tuple(redirects))
