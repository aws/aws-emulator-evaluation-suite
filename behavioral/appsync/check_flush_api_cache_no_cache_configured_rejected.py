"""flush-api-cache-no-cache-configured-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "flush-api-cache-no-cache-configured-rejected"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """FlushApiCache on a GraphQL API with no ApiCache fails NotFoundException, and stops doing so once
    CreateApiCache has created the cache resource."""
    appsync = ctx.client("appsync")

    api_id = _create_graphql_api(ctx, appsync)

    # No ApiCache has ever been created for this API.
    code, message = _error(lambda: appsync.flush_api_cache(apiId=api_id))
    assert code == "NotFoundException", f"expected NotFoundException, got {code}"
    assert message == "Unable to flush the cache as it doesn't exist, please create the cache first.", (
        f"unexpected FlushApiCache message: {message!r}"
    )

    # Boundary check: GetApiCache agrees no cache record exists either -- the rejection
    # above reflects real absence-of-cache state, not a blanket FlushApiCache failure.
    get_code, get_message = _error(lambda: appsync.get_api_cache(apiId=api_id))
    assert get_code == "NotFoundException", f"expected NotFoundException, got {get_code}"
    assert get_message == "Unable to get the cache as it doesn't exist, please create the cache first.", (
        f"unexpected GetApiCache message: {get_message!r}"
    )

    # Positive control: provision a real cache and confirm the identical calls stop
    # seeing the resource as absent -- otherwise a target that always 404s on
    # FlushApiCache/GetApiCache would score identically to a correct one.
    appsync.create_api_cache(
        apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )
    # No separate DeleteApiCache teardown: AppSync refuses it while the cache is still
    # creating, and the GraphQL API's own cleanup deletes the cache with the API.

    _poll_until(
        lambda: _flush_sees_cache(appsync, api_id),
        bool,
        timeout_s=60.0,
        interval_s=3.0,
    )

    # With the cache in place GetApiCache answers with the cache record, so the
    # NotFoundException above is presence-based.
    cache = appsync.get_api_cache(apiId=api_id)["apiCache"]
    assert cache["apiCachingBehavior"] == "FULL_REQUEST_CACHING", f"unexpected cache record {cache!r}"


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
    name = ctx.unique_name("sim2real-flushcache-")
    api = appsync.create_graphql_api(name=name, authenticationType="API_KEY")["graphqlApi"]
    api_id = api["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
