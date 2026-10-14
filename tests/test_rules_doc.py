"""Phase 12: docs/RULES.md is generated, and cannot drift from the code."""

from __future__ import annotations

import re
from pathlib import Path

from skillguard.rule_catalog import all_rules, render_rules_markdown

ROOT = Path(__file__).resolve().parent.parent
RULES_DOC = ROOT / "docs" / "RULES.md"
SOURCE = ROOT / "src" / "skillguard"

#: Any string literal that looks like a rule id, wherever it appears. Most
#: analyzers pass the id positionally (``_finding("SC8", ...)``), so matching
#: only ``rule_id="..."`` would cover barely half of them.
_CANDIDATE = re.compile(r'"([A-Z]{1,3}\d{1,2})"')


def test_rules_doc_is_up_to_date() -> None:
    expected = render_rules_markdown()
    actual = RULES_DOC.read_text(encoding="utf-8")

    assert actual == expected, (
        "docs/RULES.md is stale. Regenerate with:\n"
        "  uv run python -m skillguard.rule_catalog > docs/RULES.md"
    )


def test_every_rule_id_in_the_source_is_catalogued() -> None:
    catalogued = {rule.id for rule in all_rules()}
    # Restrict to prefixes the catalog actually uses, so unrelated literals
    # like "UTF8" are not mistaken for rule ids.
    prefixes = {re.match(r"[A-Z]+", rule.id).group() for rule in all_rules()}

    found: set[str] = set()
    for path in SOURCE.rglob("*.py"):
        for candidate in _CANDIDATE.findall(path.read_text(encoding="utf-8")):
            if re.match(r"[A-Z]+", candidate).group() in prefixes:
                found.add(candidate)

    assert found, "the scanner should mention at least one rule id"
    assert found <= catalogued, f"not in the catalog: {sorted(found - catalogued)}"


def test_rule_ids_are_unique() -> None:
    ids = [rule.id for rule in all_rules()]

    assert len(ids) == len(set(ids))


def test_every_rule_has_a_remediation() -> None:
    assert all(rule.remediation for rule in all_rules())


def test_docs_cover_every_category() -> None:
    text = RULES_DOC.read_text(encoding="utf-8")

    for category in {rule.category for rule in all_rules()}:
        assert f"## {category}" in text
