"""OSV.dev client: known vulnerabilities for pinned dependencies.

Design rules:

- only pinned versions are queried (OSV needs a concrete version),
- one batched HTTP request, not one per dependency,
- an in-memory TTL cache, so re-scanning is free,
- bounded retries, then a small static fallback list when the network fails.

Every failure degrades to the fallback. A scanner that dies because a
vulnerability database is unreachable is worse than one that reports less.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import httpx

from skillguard.constants import OSV_BATCH_URL
from skillguard.dependencies import Dependency

#: Used when OSV.dev cannot be reached. Small on purpose: it is a floor, not a
#: substitute for the live database.
FALLBACK_VULNERABILITIES: dict[tuple[str, str, str], tuple[str, ...]] = {
    ("PyPI", "pyyaml", "5.3.1"): ("CVE-2020-14343",),
    ("PyPI", "pyyaml", "5.4"): ("CVE-2020-14343",),
    ("PyPI", "requests", "2.19.0"): ("CVE-2018-18074",),
    ("PyPI", "urllib3", "1.24.1"): ("CVE-2019-9740",),
    ("npm", "lodash", "4.17.15"): ("CVE-2020-8203",),
}


@dataclass(frozen=True, slots=True)
class Vulnerability:
    """One known vulnerability affecting one dependency."""

    package: str
    ecosystem: str
    version: str
    vuln_id: str
    summary: str


def _coordinate(dependency: Dependency) -> tuple[str, str, str]:
    return (dependency.ecosystem, dependency.name.lower(), dependency.version or "")


class OsvClient:
    """Batched, cached, retrying OSV.dev client with an offline fallback."""

    def __init__(
        self,
        *,
        client: httpx.Client | None = None,
        timeout: float = 10.0,
        retries: int = 2,
        backoff_seconds: float = 0.5,
        cache_ttl: float = 3600.0,
    ) -> None:
        self._client = client if client is not None else httpx.Client(timeout=timeout)
        self._retries = retries
        self._backoff_seconds = backoff_seconds
        self._cache_ttl = cache_ttl
        self._cache: dict[tuple[str, str, str], tuple[float, list[Vulnerability]]] = {}

    # ---------------------------------------------------------------- cache

    def _cached(self, key: tuple[str, str, str]) -> list[Vulnerability] | None:
        entry = self._cache.get(key)
        if entry is None:
            return None
        stored_at, vulnerabilities = entry
        if time.monotonic() - stored_at > self._cache_ttl:
            del self._cache[key]
            return None
        return vulnerabilities

    def _store(self, key: tuple[str, str, str], vulnerabilities: list[Vulnerability]) -> None:
        self._cache[key] = (time.monotonic(), vulnerabilities)

    # --------------------------------------------------------------- network

    def _post(self, payload: dict[str, object]) -> httpx.Response:
        """POST with bounded retries. Raises the last transport error."""
        last_error: httpx.HTTPError | None = None
        for attempt in range(self._retries + 1):
            try:
                response = self._client.post(OSV_BATCH_URL, json=payload)
                response.raise_for_status()
                return response
            except httpx.HTTPError as exc:
                last_error = exc
                if attempt < self._retries:
                    time.sleep(self._backoff_seconds * (2**attempt))
        raise last_error if last_error is not None else httpx.HTTPError("request failed")

    def _fetch(self, dependencies: list[Dependency]) -> dict[str, list[Vulnerability]]:
        payload: dict[str, object] = {
            "queries": [
                {
                    "package": {"name": d.name, "ecosystem": d.ecosystem},
                    "version": d.version,
                }
                for d in dependencies
            ]
        }
        try:
            response = self._post(payload)
            body = response.json()
        except (httpx.HTTPError, ValueError):
            return self._fallback(dependencies)

        results: dict[str, list[Vulnerability]] = {}
        entries = body.get("results", []) if isinstance(body, dict) else []
        for dependency, entry in zip(dependencies, entries, strict=False):
            vulns = entry.get("vulns", []) if isinstance(entry, dict) else []
            found = [
                Vulnerability(
                    package=dependency.name,
                    ecosystem=dependency.ecosystem,
                    version=dependency.version or "",
                    vuln_id=str(vuln.get("id", "")),
                    summary=str(vuln.get("summary", "")),
                )
                for vuln in vulns
                if isinstance(vuln, dict)
            ]
            self._store(_coordinate(dependency), found)
            results[f"{dependency.name}=={dependency.version}"] = found
        return results

    def _fallback(self, dependencies: list[Dependency]) -> dict[str, list[Vulnerability]]:
        results: dict[str, list[Vulnerability]] = {}
        for dependency in dependencies:
            ids = FALLBACK_VULNERABILITIES.get(_coordinate(dependency), ())
            found = [
                Vulnerability(
                    package=dependency.name,
                    ecosystem=dependency.ecosystem,
                    version=dependency.version or "",
                    vuln_id=vuln_id,
                    summary="offline fallback entry",
                )
                for vuln_id in ids
            ]
            results[f"{dependency.name}=={dependency.version}"] = found
        return results

    # ----------------------------------------------------------------- api

    def query(self, dependencies: list[Dependency]) -> dict[str, list[Vulnerability]]:
        """Return vulnerabilities keyed by ``name==version``.

        Unpinned dependencies are skipped: OSV cannot answer for "any version".
        """
        pinned = [d for d in dependencies if d.version]
        if not pinned:
            return {}

        results: dict[str, list[Vulnerability]] = {}
        pending: list[Dependency] = []
        for dependency in pinned:
            cached = self._cached(_coordinate(dependency))
            if cached is None:
                pending.append(dependency)
            else:
                results[f"{dependency.name}=={dependency.version}"] = cached

        if pending:
            results.update(self._fetch(pending))
        return results
