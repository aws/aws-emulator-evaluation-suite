"""concurrent-update-resolver."""
from __future__ import annotations

import concurrent.futures
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _run_concurrent(fns, *, timeout_s=60):
    """Run callables in parallel; return results in submission order — each entry is the callable's
    return value or the Exception it raised (captured, NOT re-raised)."""
    results = [None] * len(fns)
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
    return sum(1 for r in results if not isinstance(r, BaseException))

def _error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get("Error", {}).get("Code"))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes

def _delete_if_present(fn):
    """Teardown for a resource the check's own delete race may already have removed."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected success
    raises, so an emulator that accepts what AWS refuses fails loudly."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _assert_update_race(results, *, racers, op_name, expected_code="ConcurrentModificationException"):
    successes = _successes(results)
    codes = _error_codes(results)
    assert successes >= 1, f"expected at least one {op_name} racer to win, got results={results!r}"
    assert successes + len(codes) == racers, (
        f"every {op_name} racer must resolve to either a success or an error, got {results!r}"
    )
    for code in codes:
        assert code == expected_code, (
            f"expected every losing {op_name} racer to fail with {expected_code}, got {code} "
            f"(all codes: {codes!r})"
        )
    return successes

def _assert_delete_race(results, *, op_name, allowed_codes=("NotFoundException", "ConcurrentModificationException")):
    successes = _successes(results)
    codes = _error_codes(results)
    assert successes == 1, f"expected exactly 1 {op_name} racer to win, got {successes} (results={results!r})"
    for code in codes:
        assert code in allowed_codes, (
            f"expected every losing {op_name} racer to fail with one of {allowed_codes}, got {code}"
        )

def _alnum(ctx, prefix):
    """A unique name with NO hyphens — required for DataSource names (``[_A-Za-z][_0-9A-Za-z]*``)."""
    return ctx.unique_name(prefix).replace("-", "_")

CHECK = "concurrent-update-resolver"
GROUP = 'concurrency'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent update/delete of the same Resolver triggers ConcurrentModificationException."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(name=ctx.unique_name("sim2real-behav-appsync-api-"), authenticationType="API_KEY")["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]

    svc.start_schema_creation(apiId=api_id, definition="schema { query: Query }\ntype Query { echo: String }".encode("utf-8"))
    _poll_until(
        lambda: svc.get_schema_creation_status(apiId=api_id),
        lambda r: r["status"] in ("SUCCESS", "ACTIVE", "FAILED", "NOT_APPLICABLE"),
        timeout_s=90, interval_s=2.0, description="schema creation to reach a terminal state",
    )

    ds = svc.create_data_source(apiId=api_id, name=_alnum(ctx, "ds"), type="NONE")["dataSource"]
    ctx.on_cleanup(lambda _n=ds["name"]: svc.delete_data_source(apiId=api_id, name=_n))
    svc.create_resolver(
        apiId=api_id,
        typeName="Query",
        fieldName="echo",
        dataSourceName=ds["name"],
        requestMappingTemplate='{"version": "2018-05-29", "operation": "Invoke"}',
        responseMappingTemplate="$util.toJson($ctx.result)",
    )
    ctx.on_cleanup(lambda: _delete_if_present(lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="echo")))
    racers = 5

    def update_attempt(i):
        return svc.update_resolver(
            apiId=api_id,
            typeName="Query",
            fieldName="echo",
            dataSourceName=ds["name"],
            requestMappingTemplate=f'{{"version": "2018-05-29", "operation": "Invoke", "race": {i}}}',
            responseMappingTemplate="$util.toJson($ctx.result)",
        )

    results = _run_concurrent([lambda i=i: update_attempt(i) for i in range(racers)])
    _assert_update_race(results, racers=racers, op_name="UpdateResolver")

    got = svc.get_resolver(apiId=api_id, typeName="Query", fieldName="echo")["resolver"]
    assert '"race"' in got["requestMappingTemplate"], (
        f"expected the winning UpdateResolver to persist, got {got!r}"
    )

    del_results = _run_concurrent(
        [lambda: svc.delete_resolver(apiId=api_id, typeName="Query", fieldName="echo") for _ in range(3)]
    )
    _assert_delete_race(del_results, op_name="DeleteResolver")

    code_after, message_after = _error(
        lambda: svc.get_resolver(apiId=api_id, typeName="Query", fieldName="echo")
    )
    assert code_after == "NotFoundException", (
        f"expected NotFoundException from GetResolver after the delete race settled, got {code_after}"
    )
    assert message_after == "No resolver found.", (
        f"expected the exact NotFound message from GetResolver, got {message_after!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
