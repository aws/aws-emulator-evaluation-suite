"""update-api-cache-concurrent-modification-rejected."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-api-cache-concurrent-modification-rejected"
GROUP = "state-machine"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateApiCache calls on one AVAILABLE cache each succeed or lose with
    ConcurrentModificationException and its exact message, at least one succeeds, and the cache
    settles AVAILABLE with a successful racer's ttl, never a refused racer's."""
    appsync = ctx.client("appsync")
    api_id = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-cache-conc-"),
        authenticationType="API_KEY",
        tags={"sim2real-audit": "true"},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _safe_delete_graphql_api(appsync, api_id))
    ctx.on_cleanup(lambda: _safe_delete_api_cache(appsync, api_id))

    appsync.create_api_cache(
        apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )
    cache = _poll_until(
        lambda: appsync.get_api_cache(apiId=api_id)["apiCache"],
        lambda c: c["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=_cap(ctx, 900.0),
        interval_s=15,
    )
    if cache is None or cache["status"] != "AVAILABLE":
        raise AssertionError(
            f"ApiCache did not reach AVAILABLE within budget (status="
            f"{cache.get('status') if cache else None!r}); cannot exercise the racing-update path",
        )

    def _update(ttl_value):
        try:
            appsync.update_api_cache(
                apiId=api_id, ttl=ttl_value, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
            )
            return ("ok", ttl_value, None)
        except Exception as exc:  # noqa: BLE001
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError):
                err = exc.response.get("Error", {})
                return ("error", err.get("Code"), err.get("Message"))
            return ("error", repr(exc), None)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_update, [500, 700]))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert successes, f"expected at least one racing UpdateApiCache to succeed, got {results}"
    for _, code, message in failures:
        assert code == "ConcurrentModificationException", (
            f"a racing UpdateApiCache may only lose with ConcurrentModificationException, "
            f"got {code!r}"
        )
        assert message == "Unable to update cache due to concurrent updates", (
            f"unexpected {code} message: {message!r}"
        )
    winning_ttls = {ttl for _, ttl, _ in successes}

    final = _poll_until(
        lambda: appsync.get_api_cache(apiId=api_id)["apiCache"],
        lambda c: c["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=_cap(ctx, 240.0),
        interval_s=10,
    )
    assert final["status"] == "AVAILABLE", f"cache update ended in {final['status']!r}"
    assert final["ttl"] in winning_ttls, (
        f"persisted ttl={final['ttl']} is not the ttl of a racer that succeeded "
        f"({sorted(winning_ttls)}); results={results}"
    )


def _cap(ctx, own_s: float, margin_s: float = 15.0) -> float:
    """Bound a wait by the check's remaining budget."""
    left = ctx.time_left()
    return own_s if left is None else max(1.0, min(own_s, left - margin_s))


def _safe_delete_graphql_api(appsync, api_id) -> None:
    from botocore.exceptions import ClientError

    try:
        appsync.delete_graphql_api(apiId=api_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _safe_delete_api_cache(appsync, api_id) -> None:
    from botocore.exceptions import ClientError

    try:
        appsync.delete_api_cache(apiId=api_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last observed: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
