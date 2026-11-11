"""schema-creation-serialization."""
from __future__ import annotations

import concurrent.futures
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

class _Unresolved:
    """Sentinel distinguishing 'never resolved' from a real success or captured exception."""

_UNRESOLVED = _Unresolved()

def _run_concurrent(fns, *, timeout_s=60):
    """Run callables in parallel; return results in submission order — each entry is the callable's
    return value, the Exception it raised (captured, NOT re-raised), or _UNRESOLVED if a slot never
    settled even after the timeout sweep."""
    results = [_UNRESOLVED] * len(fns)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                idx = future_to_idx[fut]
                try:
                    results[idx] = fut.result()
                except Exception as exc:  # noqa: BLE001 — captured for the caller to assert on
                    results[idx] = exc
        except concurrent.futures.TimeoutError:
            for pending, i in future_to_idx.items():
                if not pending.done():
                    results[i] = concurrent.futures.TimeoutError(f"call did not finish within {timeout_s}s")
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results

def _successes(results):
    return sum(1 for r in results if not isinstance(r, BaseException) and r is not _UNRESOLVED)

def _error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get("Error", {}).get("Code"))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes

_ACCEPTED = "<call accepted>"


def _error_code(fn):
    """The call's error code, or _ACCEPTED (a value no error code can equal) when it succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return _ACCEPTED

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

CHECK = "schema-creation-serialization"
GROUP = 'overly-permissive'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent StartSchemaCreation calls on one API: at least one succeeds and every other fails
    ConcurrentModificationException; once the winner settles, a further StartSchemaCreation is accepted."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(name=ctx.unique_name("sim2real-behav-appsync-api-"), authenticationType="API_KEY")["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    # DeleteGraphqlApi is refused while a schema job is in flight; let the last job settle first.
    ctx.on_cleanup(
        lambda: _poll_until(
            lambda: svc.get_schema_creation_status(apiId=api_id)["status"],
            lambda status: status in ("SUCCESS", "ACTIVE", "FAILED", "NOT_APPLICABLE"),
            timeout_s=90, interval_s=2.0, description="the last schema creation job to settle before teardown",
        )
    )
    definition = "schema { query: Query }\ntype Query { hello: String }"
    racers = 6

    def attempt():
        return svc.start_schema_creation(apiId=api_id, definition=definition.encode("utf-8"))

    results = _run_concurrent([attempt for _ in range(racers)])
    unresolved = sum(1 for r in results if r is _UNRESOLVED)
    assert unresolved == 0, f"every racer must resolve within the timeout, got {results!r}"
    successes = _successes(results)
    codes = _error_codes(results)
    assert successes >= 1, f"expected at least one StartSchemaCreation racer to win, got {results!r}"
    for code in codes:
        assert code == "ConcurrentModificationException", (
            f"expected every losing racer to fail with ConcurrentModificationException, got {code} "
            f"(all codes: {codes!r})"
        )
    # message varies: a losing racer reads either "Schema or API is currently being altered, ..." or
    # "Schema is currently being altered, ..." depending on which in-flight guard it hits.

    _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED", "NOT_APPLICABLE"),
        timeout_s=90, interval_s=2.0, description="the winning schema creation job to settle",
    )

    # The lock guarding "another job in flight" can linger briefly after the status itself reaches a
    # terminal state; retry the follow-up call for a bounded window before concluding it is
    # permanently blocked.
    followup_code = _poll_until(
        lambda: _error_code(lambda: svc.start_schema_creation(apiId=api_id, definition=definition.encode("utf-8"))),
        lambda code: code == _ACCEPTED,
        timeout_s=30, interval_s=3.0,
        description="a follow-up StartSchemaCreation to be accepted once the prior job fully settles",
    )
    assert followup_code == _ACCEPTED, (
        f"expected a NEW StartSchemaCreation after the prior job settled to be accepted, got {followup_code}"
    )

    # Independent read at the destination: the accepted follow-up must have genuinely taken effect,
    # not merely returned without raising.
    _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id)["status"],
        lambda status: status in ("PROCESSING", "SUCCESS", "ACTIVE"),
        timeout_s=30, interval_s=1.0,
        description="GetSchemaCreationStatus to independently confirm the follow-up job took effect",
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
