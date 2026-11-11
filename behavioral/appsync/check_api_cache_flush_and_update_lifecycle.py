"""api-cache-flush-and-update-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "api-cache-flush-and-update-lifecycle"
GROUP = "state-machine"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateApiCache->UpdateApiCache->FlushApiCache->GetApiCache->DeleteApiCache preserves cache
    state transitions across mutation and flush operations."""
    appsync = ctx.client("appsync")
    api_id = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-cache-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _safe(lambda: appsync.delete_graphql_api(apiId=api_id)))

    created = appsync.create_api_cache(
        apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )["apiCache"]
    assert created["ttl"] == 300, f"expected ttl 300 on create, got {created['ttl']}"
    assert created["status"] in ("CREATING", "AVAILABLE"), (
        f"unexpected status right after CreateApiCache: {created['status']}"
    )

    deleted = {"flag": False}

    def _cleanup_cache():
        if not deleted["flag"]:
            _safe(lambda: appsync.delete_api_cache(apiId=api_id))

    ctx.on_cleanup(_cleanup_cache)

    status = _wait_for_cache_status(appsync, api_id, {"AVAILABLE", "FAILED"}, timeout_s=600.0)
    if status is None:
        raise AssertionError("ApiCache did not leave CREATING within 600s")
    assert status == "AVAILABLE", f"cache creation ended in status {status}"

    updated = appsync.update_api_cache(
        apiId=api_id, ttl=600, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )["apiCache"]
    assert updated["ttl"] == 600, "UpdateApiCache did not return the new ttl"

    status2 = _wait_for_cache_status(appsync, api_id, {"AVAILABLE", "FAILED"}, timeout_s=300.0)
    if status2 is None:
        raise AssertionError("ApiCache did not settle after update within 300s")
    assert status2 == "AVAILABLE", f"cache update ended in status {status2}"

    appsync.flush_api_cache(apiId=api_id)

    got = appsync.get_api_cache(apiId=api_id)["apiCache"]
    assert got["ttl"] == 600, f"ttl not preserved across FlushApiCache, got {got['ttl']}"
    assert got["apiCachingBehavior"] == "FULL_REQUEST_CACHING", (
        f"apiCachingBehavior not preserved across FlushApiCache, got {got['apiCachingBehavior']!r}"
    )
    assert got["type"] == "SMALL", f"cache type not preserved across FlushApiCache, got {got['type']!r}"
    assert got["status"] == "AVAILABLE", (
        f"cache left AVAILABLE state after flush, got {got['status']!r}"
    )

    appsync.delete_api_cache(apiId=api_id)
    deleted["flag"] = True

    # DeleteApiCache is asynchronous on real AWS: an immediate GetApiCache right after the
    # delete call routinely still succeeds, so the not-found state must be polled for rather
    # than asserted on the very next read. GetApiCache can keep returning the cache for several
    # minutes after the delete call, so the bound is 600s.
    code, message = _wait_for_delete_notfound(appsync, api_id, timeout_s=600.0)
    assert code == "NotFoundException", (
        f"expected NotFoundException within 600s of DeleteApiCache, got {code}"
    )
    assert message == (
        "Unable to get the cache as it has been deleted, please re-create the cache."
    ), message


def _wait_for_cache_status(appsync, api_id, terminal_statuses, timeout_s):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = appsync.get_api_cache(apiId=api_id)["apiCache"]["status"]
        if status in terminal_statuses:
            return status
        time.sleep(2)
    return None


def _wait_for_delete_notfound(appsync, api_id, timeout_s):
    deadline = time.monotonic() + timeout_s
    seen = (None, None)
    while time.monotonic() < deadline:
        try:
            appsync.get_api_cache(apiId=api_id)
            seen = (None, None)
        except ClientError as e:
            err = e.response.get("Error", {})
            seen = (err.get("Code"), err.get("Message"))
            if seen[0] == "NotFoundException":
                return seen
        time.sleep(5.0)
    return seen


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
