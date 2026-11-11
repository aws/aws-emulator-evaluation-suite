"""The one classification and scoring of behavioral check results.

``classify`` reads a ``CheckResult``'s structured fields, never its detail text. ``score`` counts
``n`` as the kinds that measure the target and leaves the runner's own faults out of it.
"""

import socket
from collections import Counter
from collections.abc import Iterable
from typing import Any
from urllib.parse import urlsplit

from botocore.exceptions import ConnectTimeoutError, EndpointConnectionError

from fidelity_tests_runner.harness import (
    KNOWN_TOOLS,
    VERDICT_FAILED,
    CheckResult,
    RequiredToolMissing,
)
from fidelity_tests_runner.target import UNROUTABLE_ERROR_CODES, NonLocalHostRefused

KIND_PASSED = "passed"
#: An assertion failed: the target answered and disagreed with AWS.
KIND_FAILED = "failed"
#: An assertion failed on a published value no customer of the emulator can use.
KIND_PUBLISHED_URL = "published_url"
#: ``run(ctx)`` outlived its budget.
KIND_TIMEOUT = "timeout"
#: The target answered with an error the check did not expect, or broke a connection it accepted.
KIND_TARGET_ERROR = "target_error"
#: The target answered that it does not implement the operation.
KIND_NOT_IMPLEMENTED = "not_implemented"
#: Nothing listened at the endpoint.
KIND_NOT_UP = "not_up"
#: The runner failed: setup, a missing module, no thread, or a refused non-local host.
KIND_RUNNER_FAULT = "runner_fault"
#: The runner lacks a tool or module the check requires.
KIND_TOOL_MISSING = "tool_missing"
#: The check file did not load.
KIND_UNLOADABLE = "unloadable"

#: The kinds that measure the target: ``n`` counts these.
SCORED_KINDS = (
    KIND_PASSED,
    KIND_FAILED,
    KIND_PUBLISHED_URL,
    KIND_TIMEOUT,
    KIND_TARGET_ERROR,
    KIND_NOT_IMPLEMENTED,
)
#: The kinds that say nothing about the target, kept out of ``n``.
EXCLUDED_KINDS = (KIND_NOT_UP, KIND_RUNNER_FAULT, KIND_TOOL_MISSING, KIND_UNLOADABLE)
#: Every kind a report may carry.
KINDS = frozenset(SCORED_KINDS + EXCLUDED_KINDS)

#: ``runner_fault`` reasons.
FAULT_SETUP = "setup"
FAULT_RUNNER = "runner"
FAULT_IMPORT = "import"
FAULT_THREADS = "threads"
#: The test was about to reach a host that is not local (``target.NonLocalHostRefused``).
FAULT_HOST = "non_local_host"

#: Error codes an emulator answers for an operation it cannot route.
NOT_IMPLEMENTED_CODES = frozenset(code.lower() for code in UNROUTABLE_ERROR_CODES)

_PROBE_TIMEOUT_S = 2.0


def classify(result: CheckResult) -> str:
    """The result's kind, from its structured fields; the first that applies wins."""
    if result.unloadable:
        return KIND_UNLOADABLE
    if result.tool_missing:
        return KIND_TOOL_MISSING
    if result.runner_fault:
        return KIND_RUNNER_FAULT
    if result.not_up:
        return KIND_NOT_UP
    if result.passed:
        return KIND_PASSED
    if result.timed_out:
        return KIND_TIMEOUT
    if result.verdict == VERDICT_FAILED:
        return KIND_PUBLISHED_URL if result.published_url_violations else KIND_FAILED
    site = result.site or {}
    if (
        str(site.get("error_code") or "").lower() in NOT_IMPLEMENTED_CODES
        or site.get("error_status") == 501
    ):
        return KIND_NOT_IMPLEMENTED
    return KIND_TARGET_ERROR


def score(results: Iterable[CheckResult]) -> dict[str, Any]:
    """``tally`` of in-process results, each classified by ``classify``."""
    return tally((f"{r.service}/{r.name}", classify(r), r.cleanup_failed) for r in results)


def tally(rows: Iterable[tuple[str, str, bool]]) -> dict[str, Any]:
    """``n``, ``passed`` and ``pass_rate`` over the scored kinds, and the rest by kind.

    ``rows`` are ``(test id, kind, cleanup failed)``. Also ``failed_by_kind``,
    ``excluded_by_kind``, ``n_cleanup_failed``, ``n_total`` and ``coverage`` (``n`` over
    ``n_total``). A test that appears twice counts once: the one read last wins.
    """
    latest: dict[str, tuple[str, bool]] = {}
    for test, kind, cleanup_failed in rows:
        latest[test] = (kind, bool(cleanup_failed))
    kinds = Counter(kind for kind, _ in latest.values())
    n = sum(kinds[k] for k in SCORED_KINDS)
    total = len(latest)
    return {
        "n": n,
        "passed": kinds[KIND_PASSED],
        "pass_rate": round(kinds[KIND_PASSED] / n, 4) if n else 0.0,
        "failed_by_kind": {k: kinds[k] for k in SCORED_KINDS if k != KIND_PASSED},
        "excluded_by_kind": {k: kinds[k] for k in EXCLUDED_KINDS},
        "n_cleanup_failed": sum(failed for _, failed in latest.values()),
        "n_total": total,
        "coverage": round(n / total, 4) if total else 0.0,
    }


def _chain(exc: BaseException | None) -> list[BaseException]:
    seen: list[BaseException] = []
    while exc is not None and len(seen) < 16 and exc not in seen:
        seen.append(exc)
        exc = exc.__cause__ or exc.__context__
    return seen


def _connection_failure(exc: BaseException) -> tuple[bool, str]:
    """Whether ``exc`` (or what raised it) failed to connect, and to which host (``""`` unknown).

    A connection the target accepted and then broke, or a read that timed out, is not one.
    """
    for e in _chain(exc):
        if isinstance(e, EndpointConnectionError | ConnectTimeoutError):
            url = str(getattr(e, "kwargs", {}).get("endpoint_url") or "")
            return True, (urlsplit(url).hostname or "").lower()
        if isinstance(e, ConnectionRefusedError):
            return True, ""
        if type(e).__name__ == "NewConnectionError":  # urllib3, also under requests
            pool = getattr(e, "pool", None) or getattr(e, "conn", None)
            return True, str(getattr(pool, "host", "") or "").lower()
    return False, ""


def endpoint_listening(endpoint: str) -> bool:
    """Whether a TCP connection to ``endpoint``'s host and port succeeds now."""
    url = urlsplit(endpoint)
    port = url.port or (443 if url.scheme == "https" else 80)
    try:
        with socket.create_connection(((url.hostname or "").strip("[]"), port), _PROBE_TIMEOUT_S):
            return True
    except OSError:
        return False


def is_not_up(exc: BaseException, endpoint: str) -> bool:
    """A failure to connect to the endpoint (or to an unnamed host) while it does not listen.

    A failure on another host (a data-plane URL the target announced), or one while the endpoint
    still listens, is the target's.
    """
    failed, host = _connection_failure(exc)
    if not failed:
        return False
    own = (urlsplit(endpoint).hostname or "").lower().strip("[]")
    return host in ("", own) and not endpoint_listening(endpoint)


def runner_fault_of(exc: BaseException) -> str:
    """The ``runner_fault`` reason an exception from check code is, or ``""``."""
    if any(isinstance(e, NonLocalHostRefused) for e in _chain(exc)):
        return FAULT_HOST
    if isinstance(exc, ImportError):
        return FAULT_IMPORT
    if isinstance(exc, RuntimeError) and "can't start new thread" in str(exc):
        return FAULT_THREADS
    return ""


def missing_tools_of(exc: BaseException) -> tuple[str, ...]:
    """The tools ``exc`` says the runner lacks: ``RequiredToolMissing``, or a missing binary."""
    if isinstance(exc, RequiredToolMissing):
        return tuple(exc.tools)
    if isinstance(exc, FileNotFoundError):
        name = str(exc.filename or "").rsplit("/", 1)[-1]
        if name in KNOWN_TOOLS:
            return (name,)
    return ()
