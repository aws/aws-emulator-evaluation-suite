"""api-cache-ttl-out-of-range-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-cache-ttl-out-of-range-rejected"
GROUP = "visibility-timeout-ttl"
SERVICES = ["appsync"]

_TTL_RANGE_MESSAGE = "TTL value cannot be smaller than 1 second and larger than 3600 seconds."
_NO_CACHE_MESSAGE = "Unable to get the cache as it doesn't exist, please create the cache first."


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApiCache and UpdateApiCache reject ttl values outside the 1-3600 second window with
    BadRequestException, leaving no cache behind and the existing cache's ttl unchanged.
    """
    appsync = ctx.client("appsync")
    api_id = _create_graphql_api(ctx)

    # CreateApiCache provisions a managed ElastiCache replication group, so the first
    # CREATING -> AVAILABLE transition can take over 10 minutes.
    _create_wait_s = 600.0

    # Negative: creating a cache with ttl above the 3600s ceiling is rejected outright,
    # and no ApiCache resource is left behind.
    code, message = _error(lambda: appsync.create_api_cache(
        apiId=api_id, ttl=3601, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL",
    ))
    assert code == "BadRequestException", f"got {code!r}"
    assert message == _TTL_RANGE_MESSAGE, message
    not_found_code, not_found_message = _error(lambda: appsync.get_api_cache(apiId=api_id))
    assert not_found_code == "NotFoundException", (
        f"rejected CreateApiCache should not leave a cache behind, got {not_found_code!r}"
    )
    assert not_found_message == _NO_CACHE_MESSAGE, not_found_message

    # Positive control: a valid ttl succeeds, giving us a live cache to attack.
    appsync.create_api_cache(
        apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL",
    )
    ctx.on_cleanup(lambda: _delete_cache_ignoring_not_found(appsync, api_id))
    cache = _wait_status(
        lambda: appsync.get_api_cache(apiId=api_id)["apiCache"],
        {"AVAILABLE", "FAILED"},
        timeout_s=_create_wait_s,
        interval_s=5.0,
    )
    assert cache["status"] == "AVAILABLE", cache
    assert cache["ttl"] == 300, cache

    # Negative: updating to ttl=0 (below the 1s floor) is rejected and the existing
    # cache's ttl is left untouched.
    code, message = _error(lambda: appsync.update_api_cache(
        apiId=api_id, ttl=0, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL",
    ))
    assert code == "BadRequestException", f"got {code!r}"
    assert message == _TTL_RANGE_MESSAGE, message
    unchanged = appsync.get_api_cache(apiId=api_id)["apiCache"]
    assert unchanged["ttl"] == 300, f"ttl mutated by a rejected update: {unchanged['ttl']}"
    assert unchanged["status"] == "AVAILABLE", (
        f"rejected UpdateApiCache should not change status, got {unchanged['status']!r}"
    )

    # Negative: updating above the 3600s ceiling is rejected too, ttl still untouched.
    code, message = _error(lambda: appsync.update_api_cache(
        apiId=api_id, ttl=3601, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL",
    ))
    assert code == "BadRequestException", f"got {code!r}"
    assert message == _TTL_RANGE_MESSAGE, message
    still_unchanged = appsync.get_api_cache(apiId=api_id)["apiCache"]
    assert still_unchanged["ttl"] == 300, (
        f"ttl mutated by a rejected update: {still_unchanged['ttl']}"
    )


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-")
    resp = appsync.create_graphql_api(
        name=name, authenticationType="API_KEY", tags={"env": "test"}
    )
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _delete_cache_ignoring_not_found(appsync, api_id: str) -> None:
    try:
        appsync.delete_api_cache(apiId=api_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NotFoundException":
            raise


def _error(fn: Callable[[], Any]):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _wait_status(probe: Callable[[], Any], terminal_statuses, timeout_s: float = 300.0,
                  interval_s: float = 10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if last.get("status") in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"never reached {terminal_statuses} within {timeout_s}s; last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
