"""op-contract-delete-api-cache."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-delete-api-cache"
GROUP = "error-semantics"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteApiCache removes a real ApiCache once it reaches AVAILABLE, and a second DeleteApiCache
    on the API, which no longer has a cache, succeeds as a no-op (measured on real AWS)."""
    appsync = ctx.client("appsync")
    # CreateApiCache provisions a managed, always-encrypted ElastiCache replication group behind the
    # scenes, whose CREATING -> AVAILABLE latency has been observed above 180s on real AWS. That
    # transition gets 600s; the DELETING -> gone teardown of the replication group can outlast
    # 300s, so it gets 900s.
    # Their sum fits the 1800s per-check ceiling the declared waits give behavioral/appsync.
    _create_wait_s = 600.0
    _delete_wait_s = 900.0

    api_id = _create_graphql_api(ctx)

    appsync.create_api_cache(
        apiId=api_id,
        ttl=300,
        apiCachingBehavior="FULL_REQUEST_CACHING",
        type="SMALL",
    )
    cache_deleted = {"done": False}
    ctx.on_cleanup(lambda: None if cache_deleted["done"] else appsync.delete_api_cache(apiId=api_id))

    status = _poll_until(
        lambda: appsync.get_api_cache(apiId=api_id)["apiCache"]["status"],
        lambda s: s in ("AVAILABLE", "FAILED"),
        timeout_s=_create_wait_s,
        interval_s=5.0,
    )
    if status != "AVAILABLE":
        raise AssertionError(
            f"ApiCache never reached AVAILABLE (status={status})",
        )

    appsync.delete_api_cache(apiId=api_id)
    cache_deleted["done"] = True

    final_status = _poll_until(
        lambda: _get_cache_status_or_none(appsync, api_id),
        lambda s: s is None,
        timeout_s=_delete_wait_s,
        interval_s=5.0,
    )
    assert final_status is None, f"ApiCache still present after delete, status={final_status}"

    code, message = _expect_refused(lambda: appsync.get_api_cache(apiId=api_id))
    assert code == "NotFoundException", f"expected NotFoundException after delete, got {code}"
    assert message == "Unable to get the cache as it has been deleted, please re-create the cache.", (
        f"expected the exact NotFoundException message AWS returns, got {message!r}"
    )

    # Boundary: deleting a cache that no longer exists is idempotent, not an error.
    try:
        appsync.delete_api_cache(apiId=api_id)
        no_op_code = None
    except ClientError as exc:
        no_op_code = exc.response["Error"]["Code"]
    assert no_op_code is None, f"expected the redundant delete to succeed as a no-op, got {no_op_code}"
    code3, message3 = _expect_refused(lambda: appsync.get_api_cache(apiId=api_id))
    assert code3 == "NotFoundException", f"expected the cache to stay gone, got {code3}"
    assert message3 == "Unable to get the cache as it doesn't exist, please create the cache first.", (
        f"expected the exact NotFoundException message AWS returns, got {message3!r}"
    )


def _create_graphql_api(ctx) -> str:
    appsync = ctx.client("appsync")
    resp = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-behav-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )
    api_id = resp["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: appsync.delete_graphql_api(apiId=api_id))
    return api_id


def _get_cache_status_or_none(appsync, api_id: str):
    from botocore.exceptions import ClientError

    try:
        return appsync.get_api_cache(apiId=api_id)["apiCache"]["status"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NotFoundException":
            return None
        raise


def _poll_until(probe, predicate, *, timeout_s=900, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


def _expect_refused(fn):
    """Call fn() expecting it to be refused; return (code, message). Raises if fn() succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
