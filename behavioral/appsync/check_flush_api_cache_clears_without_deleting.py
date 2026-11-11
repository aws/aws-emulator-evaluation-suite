"""flush-api-cache-clears-without-deleting."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "flush-api-cache-clears-without-deleting"
GROUP = "visibility-timeout-ttl"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FlushApiCache leaves the ApiCache ACTIVE with its ttl/behavior/type unchanged, while
    DeleteApiCache removes it: GetApiCache and a further FlushApiCache then fail NotFoundException."""
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)

    started = time.monotonic()
    overall_budget_s = 1500.0

    def _remaining() -> float:
        return max(0.0, overall_budget_s - (time.monotonic() - started))

    appsync.create_api_cache(
        apiId=api_id,
        ttl=300,
        apiCachingBehavior="FULL_REQUEST_CACHING",
        type="SMALL",
        healthMetricsConfig="DISABLED",
    )
    ctx.on_cleanup(lambda: _delete_cache_ignoring_not_found(appsync, api_id))

    try:
        cache = _poll_until(
            lambda: appsync.get_api_cache(apiId=api_id)["apiCache"]["status"],
            lambda s: s in ("AVAILABLE", "FAILED"),
            timeout_s=max(30.0, _remaining() - 40.0),
            interval_s=10,
        )
    except AssertionError:
        raise AssertionError(
            "ApiCache was still CREATING when the check's bounded poll window closed; "
            "CreateApiCache's ElastiCache-backed provisioning can legitimately take "
            "longer than the harness's whole-check budget on real AWS"
        )
    assert cache == "AVAILABLE", f"cache never reached AVAILABLE (status={cache})"

    before = appsync.get_api_cache(apiId=api_id)["apiCache"]
    assert before["ttl"] == 300, f"expected ttl=300 from an independent GetApiCache read, got {before['ttl']!r}"
    assert before["apiCachingBehavior"] == "FULL_REQUEST_CACHING", (
        f"expected apiCachingBehavior=FULL_REQUEST_CACHING, got {before['apiCachingBehavior']!r}"
    )
    assert before["type"] == "SMALL", f"expected type=SMALL, got {before['type']!r}"

    # FlushApiCache purges cache entries; it must NOT delete or degrade the cache resource.
    flush_resp = appsync.flush_api_cache(apiId=api_id)
    assert flush_resp["ResponseMetadata"]["HTTPStatusCode"] == 200, (
        f"expected FlushApiCache to return 200, got {flush_resp['ResponseMetadata']['HTTPStatusCode']!r}"
    )

    status_after_flush = _poll_until(
        lambda: appsync.get_api_cache(apiId=api_id)["apiCache"]["status"],
        lambda s: s == "AVAILABLE",
        timeout_s=max(15.0, _remaining() - 60.0),
        interval_s=3,
    )
    assert status_after_flush == "AVAILABLE", (
        f"ApiCache resource was disturbed by FlushApiCache (status={status_after_flush})"
    )
    after_flush = appsync.get_api_cache(apiId=api_id)["apiCache"]
    assert after_flush["ttl"] == 300, f"flush must not mutate ttl, got {after_flush['ttl']!r}"
    assert after_flush["apiCachingBehavior"] == "FULL_REQUEST_CACHING", (
        f"flush must not mutate apiCachingBehavior, got {after_flush['apiCachingBehavior']!r}"
    )
    assert after_flush["type"] == "SMALL", f"flush must not mutate type, got {after_flush['type']!r}"

    # DeleteApiCache, in contrast, removes the resource entirely.
    appsync.delete_api_cache(apiId=api_id)

    final = _poll_until(
        lambda: _cache_status_or_gone(appsync, api_id),
        lambda s: s == "GONE",
        timeout_s=max(10.0, _remaining()),
        interval_s=5,
    )
    assert final == "GONE", "ApiCache resource still present after DeleteApiCache"
    read_code, read_message = _error(lambda: appsync.get_api_cache(apiId=api_id))
    assert read_code == "NotFoundException", (
        f"expected an independent GetApiCache read to report NotFoundException after delete, got {read_code!r}"
    )
    expected = "Unable to get the cache as it has been deleted, please re-create the cache."
    assert read_message == expected, f"expected GetApiCache message {expected!r}, got {read_message!r}"

    # A mutation on the now-dead id must also fail NotFoundException, not silently no-op --
    # this is the same id DeleteApiCache and the earlier FlushApiCache both operated on above.
    mutate_code, mutate_message = _error(lambda: appsync.flush_api_cache(apiId=api_id))
    assert mutate_code == "NotFoundException", (
        f"expected FlushApiCache on a deleted cache id to fail NotFoundException, got {mutate_code!r}"
    )
    expected = "Unable to flush the cache as it has been deleted, please re-create the cache."
    assert mutate_message == expected, f"expected FlushApiCache message {expected!r}, got {mutate_message!r}"


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")
    resp = appsync.create_graphql_api(name=name, authenticationType="API_KEY")
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _delete_cache_ignoring_not_found(appsync, api_id: str) -> None:
    try:
        appsync.delete_api_cache(apiId=api_id)
    except ClientError as exc:
        # BadRequestException: the cache is already DELETING, so the delete is under way.
        if exc.response["Error"]["Code"] not in ("NotFoundException", "BadRequestException"):
            raise


def _cache_status_or_gone(appsync, api_id: str) -> str:
    try:
        return appsync.get_api_cache(apiId=api_id)["apiCache"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NotFoundException":
            return "GONE"
        raise


def _error(fn: Callable[[], Any]):
    """Call fn(); return its error (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool],
                 timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"predicate never satisfied within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
