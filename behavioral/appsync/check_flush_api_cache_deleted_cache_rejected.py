"""flush-api-cache-deleted-cache-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "flush-api-cache-deleted-cache-rejected"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteApiCache, FlushApiCache and GetApiCache report NotFoundException on an API with no cache,
    and once CreateApiCache creates the cache resource, GetApiCache and FlushApiCache find it."""
    appsync = ctx.client("appsync")

    api_id = _create_graphql_api(ctx, appsync)

    # DeleteApiCache on an API that has no ApiCache at all correctly reports
    # NotFoundException -- it does not silently no-op with a 200.
    delete_code, delete_message = _error(lambda: appsync.delete_api_cache(apiId=api_id))
    assert delete_code == "NotFoundException", f"expected NotFoundException, got {delete_code}"
    assert delete_message == "Unable to delete the cache as it doesn't exist, please create the cache first.", (
        f"unexpected delete_api_cache message: {delete_message!r}"
    )

    # With the cache confirmed absent, FlushApiCache on the same API is rejected the
    # same way -- the two ops agree on the resource's nonexistence.
    flush_code, flush_message = _error(lambda: appsync.flush_api_cache(apiId=api_id))
    assert flush_code == "NotFoundException", f"expected NotFoundException, got {flush_code}"
    assert flush_message == "Unable to flush the cache as it doesn't exist, please create the cache first.", (
        f"unexpected flush_api_cache message: {flush_message!r}"
    )

    # GetApiCache agrees too: no cache record exists to retrieve.
    get_code, get_message = _error(lambda: appsync.get_api_cache(apiId=api_id))
    assert get_code == "NotFoundException", f"expected NotFoundException, got {get_code}"
    assert get_message == "Unable to get the cache as it doesn't exist, please create the cache first.", (
        f"unexpected get_api_cache message: {get_message!r}"
    )

    # Positive control: create a real ApiCache (resource creation is synchronous) and
    # confirm the identical GetApiCache/FlushApiCache calls no longer see it as absent --
    # a target that rejects every ApiCache call regardless of state fails this leg.
    appsync.create_api_cache(
        apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )
    # No separate DeleteApiCache teardown: AppSync refuses it while the cache is still
    # creating, and the GraphQL API's own cleanup deletes the cache with the API.

    # With the cache in place GetApiCache answers with the cache record, so the rejection
    # above is presence-based.
    cache = appsync.get_api_cache(apiId=api_id)["apiCache"]
    assert cache["apiCachingBehavior"] == "FULL_REQUEST_CACHING", f"unexpected cache record {cache!r}"

    _poll_until(
        lambda: _flush_sees_cache(appsync, api_id),
        bool,
        timeout_s=60.0,
        interval_s=3.0,
    )


def _error(fn):
    """Call fn() and return its botocore error (code, message); a call that succeeds raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _flush_sees_cache(appsync, api_id) -> bool:
    """True once FlushApiCache no longer answers NotFoundException (success or any other refusal)."""
    from botocore.exceptions import ClientError

    try:
        appsync.flush_api_cache(apiId=api_id)
    except ClientError as err:
        return err.response["Error"]["Code"] != "NotFoundException"
    return True


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value={last!r}")


def _create_graphql_api(ctx, appsync) -> str:
    name = ctx.unique_name("sim2real-flushdeleted-")
    api = appsync.create_graphql_api(
        name=name,
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)


