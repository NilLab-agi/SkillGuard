"""Phase 10: the OSV.dev client and the SC4 rule."""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from skillguard.constants import OSV_BATCH_URL
from skillguard.dependencies import Dependency
from skillguard.discovery import discover
from skillguard.nodes.analyzers.supply_chain_osv import supply_chain_osv
from skillguard.providers.osv import FALLBACK_VULNERABILITIES, OsvClient
from skillguard.state import ScanState

PYPI_DEP = Dependency("pyyaml", "5.3.1", "==5.3.1", "PyPI", "requirements.txt", 1)
UNPINNED = Dependency("requests", None, "", "PyPI", "requirements.txt", 2)


def _vuln_response(vuln_id: str = "CVE-2020-14343") -> dict[str, object]:
    return {"results": [{"vulns": [{"id": vuln_id, "summary": "yaml deserialisation"}]}]}


def test_batch_payload_uses_pinned_coordinates(httpx_mock) -> None:  # noqa: ANN001
    httpx_mock.add_response(url=OSV_BATCH_URL, json={"results": [{}]})

    OsvClient(retries=0).query([PYPI_DEP])

    payload = json.loads(httpx_mock.get_requests()[0].content)
    assert payload["queries"] == [
        {"package": {"name": "pyyaml", "ecosystem": "PyPI"}, "version": "5.3.1"}
    ]


def test_vulnerabilities_are_returned(httpx_mock) -> None:  # noqa: ANN001
    httpx_mock.add_response(url=OSV_BATCH_URL, json=_vuln_response())

    results = OsvClient(retries=0).query([PYPI_DEP])

    assert [v.vuln_id for v in results["pyyaml==5.3.1"]] == ["CVE-2020-14343"]


def test_unpinned_dependencies_are_never_queried(httpx_mock) -> None:  # noqa: ANN001
    results = OsvClient(retries=0).query([UNPINNED])

    assert results == {}
    assert httpx_mock.get_requests() == []


def test_repeated_queries_hit_the_cache(httpx_mock) -> None:  # noqa: ANN001
    httpx_mock.add_response(url=OSV_BATCH_URL, json=_vuln_response())
    client = OsvClient(retries=0)

    first = client.query([PYPI_DEP])
    second = client.query([PYPI_DEP])

    assert first == second
    assert len(httpx_mock.get_requests()) == 1


def test_transport_error_falls_back_to_the_static_list(httpx_mock) -> None:  # noqa: ANN001
    httpx_mock.add_exception(httpx.ConnectError("no network"))

    results = OsvClient(retries=0).query([PYPI_DEP])

    expected = FALLBACK_VULNERABILITIES[("PyPI", "pyyaml", "5.3.1")]
    assert [v.vuln_id for v in results["pyyaml==5.3.1"]] == list(expected)


def test_malformed_response_falls_back(httpx_mock) -> None:  # noqa: ANN001
    httpx_mock.add_response(url=OSV_BATCH_URL, content=b"not json at all")

    results = OsvClient(retries=0).query([PYPI_DEP])

    assert results["pyyaml==5.3.1"]


def test_transient_failure_is_retried(httpx_mock) -> None:  # noqa: ANN001
    httpx_mock.add_exception(httpx.ConnectError("flaky"))
    httpx_mock.add_response(url=OSV_BATCH_URL, json=_vuln_response("CVE-2021-1"))

    results = OsvClient(retries=1, backoff_seconds=0.0).query([PYPI_DEP])

    assert [v.vuln_id for v in results["pyyaml==5.3.1"]] == ["CVE-2021-1"]
    assert len(httpx_mock.get_requests()) == 2


def test_server_error_falls_back(httpx_mock) -> None:  # noqa: ANN001
    httpx_mock.add_response(url=OSV_BATCH_URL, status_code=503)

    results = OsvClient(retries=0).query([PYPI_DEP])

    assert results["pyyaml==5.3.1"]


# ------------------------------------------------------------------- SC4 node


def _skill(tmp_path: Path, requirements: str) -> ScanState:
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "requirements.txt").write_text(requirements, encoding="utf-8")
    return ScanState(
        context=discover(str(skill), max_files=50, max_file_bytes=100_000),
        use_osv=True,
    )


def test_sc4_reports_a_known_vulnerability(tmp_path: Path, httpx_mock) -> None:  # noqa: ANN001
    httpx_mock.add_response(url=OSV_BATCH_URL, json=_vuln_response())

    update = supply_chain_osv(_skill(tmp_path, "pyyaml==5.3.1\n"))
    findings = update["findings"]

    assert isinstance(findings, list)
    assert [f.rule_id for f in findings] == ["SC4"]
    assert "CVE-2020-14343" in findings[0].message
    assert findings[0].location.file == "requirements.txt"
    assert findings[0].location.start_line == 1


def test_sc4_is_off_unless_requested(tmp_path: Path, httpx_mock) -> None:  # noqa: ANN001
    state = _skill(tmp_path, "pyyaml==5.3.1\n")
    state["use_osv"] = False

    assert supply_chain_osv(state) == {"findings": []}
    assert httpx_mock.get_requests() == []


def test_sc4_ignores_a_skill_with_no_pinned_dependencies(tmp_path: Path, httpx_mock) -> None:  # noqa: ANN001
    assert supply_chain_osv(_skill(tmp_path, "requests\n")) == {"findings": []}
    assert httpx_mock.get_requests() == []


def test_multiple_advisories_aggregate_into_one_finding(tmp_path: Path, httpx_mock) -> None:  # noqa: ANN001
    httpx_mock.add_response(
        url=OSV_BATCH_URL,
        json={"results": [{"vulns": [{"id": "GHSA-1"}, {"id": "PYSEC-2"}]}]},
    )

    update = supply_chain_osv(_skill(tmp_path, "pyyaml==5.3.1\n"))
    findings = update["findings"]

    assert isinstance(findings, list)
    assert len(findings) == 1
    assert "GHSA-1" in findings[0].message
    assert "PYSEC-2" in findings[0].message
