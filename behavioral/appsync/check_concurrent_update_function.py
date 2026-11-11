"""concurrent-update-function."""
from __future__ import annotations

import concurrent.futures

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _run_concurrent(fns, *, timeout_s=60):
    """Run callables in parallel; return results in submission order. Each entry is either the
    callable's return value or the Exception it raised (captured, NOT re-raised), so a check can
    assert on the DISTRIBUTION of outcomes. Never used as a context manager (its __exit__ would
    wait for every future and defeat the timeout)."""
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

def _assert_update_race(results, *, racers, op_name, expected_code="ConcurrentModificationException"):
    """Every racer in an N-way "same mutation on the same resource" race must resolve to either a
    success or ``expected_code`` — never an unrelated error, and never every racer failing. Returns
    the success count."""
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
    """Exactly one concurrent Delete against the same resource may succeed; every other must fail
    with a referential-integrity or concurrency-conflict code."""
    successes = _successes(results)
    codes = _error_codes(results)
    assert successes == 1, f"expected exactly 1 {op_name} racer to win, got {successes} (results={results!r})"
    for code in codes:
        assert code in allowed_codes, (
            f"expected every losing {op_name} racer to fail with one of {allowed_codes}, got {code}"
        )

def _alnum(ctx, prefix):
    """A unique name with NO hyphens — required for DataSource/Function names, which only allow
    ``[_A-Za-z][_0-9A-Za-z]*``."""
    return ctx.unique_name(prefix).replace("-", "_")

CHECK = "concurrent-update-function"
GROUP = 'concurrency'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent update/delete of the same Function triggers ConcurrentModificationException."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    ds = svc.create_data_source(apiId=api_id, name=_alnum(ctx, "ds"), type="NONE")["dataSource"]
    ctx.on_cleanup(lambda _n=ds["name"]: svc.delete_data_source(apiId=api_id, name=_n))
    fn_name = _alnum(ctx, "fn")
    fn = svc.create_function(
        apiId=api_id,
        name=fn_name,
        dataSourceName=ds["name"],
        requestMappingTemplate='{"version": "2018-05-29", "operation": "Invoke"}',
        responseMappingTemplate="$util.toJson($ctx.result)",
        functionVersion="2018-05-29",
    )["functionConfiguration"]
    function_id = fn["functionId"]
    ctx.on_cleanup(lambda _f=function_id: _delete_if_present(lambda: svc.delete_function(apiId=api_id, functionId=_f)))
    racers = 5

    def update_attempt(i):
        return svc.update_function(
            apiId=api_id,
            name=fn_name,
            functionId=function_id,
            dataSourceName=ds["name"],
            requestMappingTemplate=f'{{"version": "2018-05-29", "operation": "Invoke", "race": {i}}}',
            responseMappingTemplate="$util.toJson($ctx.result)",
            functionVersion="2018-05-29",
        )

    results = _run_concurrent([lambda i=i: update_attempt(i) for i in range(racers)])
    _assert_update_race(results, racers=racers, op_name="UpdateFunction")

    got = svc.get_function(apiId=api_id, functionId=function_id)["functionConfiguration"]
    assert '"race"' in got["requestMappingTemplate"], (
        f"expected the winning UpdateFunction to persist, got {got!r}"
    )

    del_results = _run_concurrent(
        [lambda: svc.delete_function(apiId=api_id, functionId=function_id) for _ in range(3)]
    )
    _assert_delete_race(del_results, op_name="DeleteFunction")

    code_after, message_after = _error(lambda: svc.get_function(apiId=api_id, functionId=function_id))
    assert code_after == "NotFoundException", (
        f"expected NotFoundException from GetFunction after the delete race settled, got {code_after}"
    )
    assert message_after == f"function id {function_id} not found", (
        f"expected the exact NotFound message from GetFunction, got {message_after!r}"
    )

    update_after, update_message = _error(lambda: update_attempt(racers))
    assert update_after == "NotFoundException", (
        f"expected UpdateFunction on the deleted functionId to also fail with NotFoundException, "
        f"got {update_after}"
    )
    assert update_message == f"function id {function_id} not found", (
        f"expected the exact NotFound message from UpdateFunction, got {update_message!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
