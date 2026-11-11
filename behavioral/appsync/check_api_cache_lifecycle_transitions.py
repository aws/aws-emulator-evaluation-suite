"""api-cache-lifecycle-transitions."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-cache-lifecycle-transitions"
GROUP = "state"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApiCache goes CREATING -> AVAILABLE, UpdateApiCache applies the new ttl and returns to
    AVAILABLE, and after DeleteApiCache both GetApiCache and FlushApiCache return NotFoundException.
    """

    appsync = ctx.client("appsync")
    _create_wait_s = 600.0
    _update_wait_s = 300.0
    _delete_wait_s = 600.0

    api_id = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))

    appsync.create_api_cache(
        apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )

    def _cleanup_cache():
        # DeleteApiCache is refused with BadRequestException while the cache is not yet
        # AVAILABLE; retry that code within the cleanup budget, raise anything else.
        deadline = time.monotonic() + 600.0
        while True:
            try:
                appsync.delete_api_cache(apiId=api_id)
                return
            except ClientError as e:
                code = e.response.get("Error", {}).get("Code")
                if code == "NotFoundException":
                    return
                if code != "BadRequestException" or time.monotonic() >= deadline:
                    raise
            time.sleep(2.0)

    ctx.on_cleanup(_cleanup_cache)

    cache = _wait_status(
        lambda: appsync.get_api_cache(apiId=api_id)["apiCache"],
        {"AVAILABLE", "FAILED"},
        timeout_s=_create_wait_s,
        interval_s=5.0,
    )
    assert cache["status"] == "AVAILABLE", cache
    assert cache["ttl"] == 300, cache

    appsync.update_api_cache(
        apiId=api_id, ttl=600, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )
    cache = _wait_status(
        lambda: appsync.get_api_cache(apiId=api_id)["apiCache"],
        {"AVAILABLE", "FAILED"},
        timeout_s=_update_wait_s,
        interval_s=5.0,
    )
    assert cache["status"] == "AVAILABLE", cache
    assert cache["ttl"] == 600, cache

    appsync.delete_api_cache(apiId=api_id)
    deadline = time.monotonic() + _delete_wait_s
    gone = None
    while time.monotonic() < deadline:
        try:
            appsync.get_api_cache(apiId=api_id)
        except ClientError as e:
            err = e.response.get("Error", {})
            if err.get("Code") == "NotFoundException":
                gone = err.get("Message")
                break
            raise
        time.sleep(5)
    assert gone is not None, "ApiCache was never fully removed after DeleteApiCache"
    assert gone == (
        "Unable to get the cache as it has been deleted, please re-create the cache."
    ), gone

    flush_code, flush_message = _error(lambda: appsync.flush_api_cache(apiId=api_id))
    assert flush_code == "NotFoundException", (
        f"FlushApiCache on a deleted cache should 404, got {flush_code}"
    )
    assert flush_message == (
        "Unable to flush the cache as it has been deleted, please re-create the cache."
    ), flush_message


# ===== helpers =====


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _wait_status(probe, terminal_statuses, timeout_s=900, interval_s=10.0):
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

