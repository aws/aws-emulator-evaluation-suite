"""flush-api-cache-clears-state."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "flush-api-cache-clears-state"
GROUP = "visibility-timeout-ttl"
SERVICES = ["appsync"]

# CreateApiCache's ElastiCache-backed node routinely stays CREATING for well over 250s; an update
# of an already-provisioned cache is a lighter transition, so it gets a smaller bound.
_CACHE_CREATE_TIMEOUT_S = 1500.0
_CACHE_UPDATE_TIMEOUT_S = 200.0
_CACHE_POLL_S = 5.0


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """FlushApiCache clears cache state without touching the cache resource's configured
    TTL/type/behavior or its status, whereas UpdateApiCache is what actually changes TTL."""
    appsync = ctx.client("appsync")

    api_id = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-cache-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _safe_delete_graphql_api(appsync, api_id))

    appsync.create_api_cache(
        apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )
    ctx.on_cleanup(lambda: _safe_delete_api_cache(appsync, api_id))

    status = _poll_cache_status(appsync, api_id, {"AVAILABLE", "FAILED"}, _CACHE_CREATE_TIMEOUT_S)
    if status != "AVAILABLE":
        raise AssertionError(
            f"ApiCache did not reach AVAILABLE in time (status={status})"
        )

    before = appsync.get_api_cache(apiId=api_id)["apiCache"]
    assert before["ttl"] == 300, f"expected ttl=300 as configured, got {before['ttl']!r}"
    assert before["apiCachingBehavior"] == "FULL_REQUEST_CACHING", (
        f"expected apiCachingBehavior='FULL_REQUEST_CACHING' as configured, "
        f"got {before['apiCachingBehavior']!r}"
    )
    assert before["type"] == "SMALL", f"expected type='SMALL' as configured, got {before['type']!r}"
    assert before["status"] == "AVAILABLE", (
        f"expected status='AVAILABLE' after polling settled, got {before['status']!r}"
    )

    appsync.flush_api_cache(apiId=api_id)

    after_flush = appsync.get_api_cache(apiId=api_id)["apiCache"]
    assert after_flush["ttl"] == 300, "FlushApiCache must not alter the configured TTL"
    assert after_flush["apiCachingBehavior"] == "FULL_REQUEST_CACHING", (
        "FlushApiCache must not alter the configured caching behavior"
    )
    assert after_flush["type"] == "SMALL", "FlushApiCache must not alter the configured cache type"
    assert after_flush["status"] == "AVAILABLE", (
        f"FlushApiCache must not move the cache out of AVAILABLE, got {after_flush['status']!r}"
    )

    appsync.update_api_cache(
        apiId=api_id, ttl=600, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )
    status = _poll_cache_status(appsync, api_id, {"AVAILABLE", "FAILED"}, _CACHE_UPDATE_TIMEOUT_S)
    if status != "AVAILABLE":
        raise AssertionError(f"ApiCache update did not settle in time (status={status})")

    after_update = appsync.get_api_cache(apiId=api_id)["apiCache"]
    assert after_update["ttl"] == 600, (
        f"UpdateApiCache should have changed ttl to 600, got {after_update['ttl']}"
    )



def _poll_cache_status(appsync: Any, api_id: str, terminal: set[str], timeout_s: float) -> str:
    deadline = time.monotonic() + timeout_s
    last = "UNKNOWN"
    while time.monotonic() < deadline:
        try:
            last = appsync.get_api_cache(apiId=api_id)["apiCache"]["status"]
        except Exception:  # noqa: BLE001
            last = "UNKNOWN"
        if last in terminal:
            return last
        time.sleep(_CACHE_POLL_S)
    return last


def _safe_delete_api_cache(appsync: Any, api_id: str) -> None:
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            appsync.delete_api_cache(apiId=api_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "ConcurrentModificationException":
                raise
            time.sleep(5.0)
    raise AssertionError(f"delete_api_cache for {api_id} still ConcurrentModificationException after 120s")


def _safe_delete_graphql_api(appsync: Any, api_id: str) -> None:
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        try:
            appsync.delete_graphql_api(apiId=api_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "NotFoundException":
                return
            if code != "ConcurrentModificationException":
                raise
            time.sleep(5.0)
    raise AssertionError(f"delete_graphql_api for {api_id} still ConcurrentModificationException after 90s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
