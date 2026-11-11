"""concurrent-update-api-cache."""
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

def _errors(results):
    """The (code, message) of every failed result; a non-ClientError keeps its type name."""
    errors = []
    for r in results:
        if isinstance(r, ClientError):
            errors.append((r.response["Error"]["Code"], r.response["Error"].get("Message")))
        elif isinstance(r, BaseException):
            errors.append((type(r).__name__, str(r)))
    return errors

def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED: {result!r}")

def _cache_error(svc, api_id):
    """GetApiCache's (code, message) once it fails; ("present", status) while the cache resolves."""
    try:
        cache = svc.get_api_cache(apiId=api_id)["apiCache"]
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return "present", cache["status"]

def _ignore_not_found(fn):
    """Teardown for a cache the check's own delete race already removed."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

def _assert_update_race(
    results, *, racers, op_name, expected_code="ConcurrentModificationException",
    expected_message="Unable to update cache due to concurrent updates",
):
    successes = _successes(results)
    errors = _errors(results)
    assert successes >= 1, f"expected at least one {op_name} racer to win, got results={results!r}"
    assert successes + len(errors) == racers, (
        f"every {op_name} racer must resolve to either a success or an error, got {results!r}"
    )
    for code, msg in errors:
        assert code == expected_code, (
            f"expected every losing {op_name} racer to fail with {expected_code}, got {code} "
            f"(all errors: {errors!r})"
        )
        assert msg == expected_message, f"unexpected {code} message: {msg!r}"
    return successes

def _assert_delete_race(results, *, op_name, allowed_codes=("NotFoundException", "ConcurrentModificationException")):
    successes = _successes(results)
    errors = _errors(results)
    # Real AppSync accepts a second DeleteApiCache while the first is still tearing the cache down,
    # so more than one racer can win; every loser must still be a clean refusal.
    assert successes >= 1, f"expected at least 1 {op_name} racer to win, got {successes} (results={results!r})"
    # message varies: real AWS lets every DeleteApiCache racer win, so no losing message exists to pin.
    for code, _msg in errors:
        assert code in allowed_codes, (
            f"expected every losing {op_name} racer to fail with one of {allowed_codes}, got {code}"
        )

CHECK = "concurrent-update-api-cache"
GROUP = 'concurrency'
SERVICES = ['appsync']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Concurrent update/delete of the same ApiCache triggers ConcurrentModificationException."""
    svc = ctx.client("appsync")
    api = svc.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-appsync-api-"), authenticationType="API_KEY", tags={"env": "test"}
    )["graphqlApi"]
    ctx.on_cleanup(lambda _a=api: svc.delete_graphql_api(apiId=_a["apiId"]))
    api_id = api["apiId"]
    svc.create_api_cache(apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL")
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: svc.delete_api_cache(apiId=api_id)))

    def _get_cache():
        return svc.get_api_cache(apiId=api_id)["apiCache"]

    state = _poll_until(
        _get_cache,
        lambda c: c["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=600, interval_s=10.0, description="ApiCache to reach AVAILABLE",
    )
    assert state["status"] == "AVAILABLE", f"ApiCache provisioning ended {state['status']!r}"

    racers = 5
    attempted_ttls = {300 + i * 10 for i in range(racers)}

    def update_attempt(ttl):
        return svc.update_api_cache(
            apiId=api_id, ttl=ttl, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
        )

    results = _run_concurrent([lambda ttl=300 + i * 10: update_attempt(ttl) for i in range(racers)])
    _assert_update_race(results, racers=racers, op_name="UpdateApiCache")

    winner = next(r for r in results if not isinstance(r, BaseException))
    assert winner["apiCache"]["ttl"] in attempted_ttls, (
        f"expected the winning UpdateApiCache's ttl to be one of the racing values, got {winner!r}"
    )

    del_results = _run_concurrent([lambda: svc.delete_api_cache(apiId=api_id) for _ in range(2)])
    _assert_delete_race(del_results, op_name="DeleteApiCache")

    # The cache lingers as DELETING after the winning delete; wait for the terminal not-found.
    code_after, msg_after = _poll_until(
        lambda: _cache_error(svc, api_id),
        lambda err: err[0] != "present",
        timeout_s=600, interval_s=10.0, description="ApiCache to disappear after the delete race",
    )
    assert code_after == "NotFoundException", (
        f"expected NotFoundException from GetApiCache after the delete race settled, got {code_after}"
    )
    assert msg_after == "Unable to get the cache as it has been deleted, please re-create the cache.", (
        f"unexpected message: {msg_after!r}"
    )

    update_after_delete_code, update_after_delete_msg = _error(
        lambda: svc.update_api_cache(apiId=api_id, ttl=600, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL")
    )
    assert update_after_delete_code == "NotFoundException", (
        f"expected UpdateApiCache on the deleted cache to fail with NotFoundException, got "
        f"{update_after_delete_code}"
    )
    assert update_after_delete_msg == (
        "Unable to update the cache as it has been deleted, please re-create the cache."
    ), f"unexpected message: {update_after_delete_msg!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
