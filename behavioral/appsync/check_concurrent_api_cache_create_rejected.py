"""concurrent-api-cache-create-rejected."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-api-cache-create-rejected"
GROUP = "state-machine"
SERVICES = ["appsync"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent CreateApiCache calls on the same Api race: exactly one wins, the loser gets
    BadRequestException("The API has already enabled caching.") -- an already-exists validation,
    distinct from the ConcurrentModificationException reserved for racing updates of an EXISTING cache."""
    appsync = ctx.client("appsync")
    name = ctx.unique_name("sim2real-behav-apicache-race-")
    api_id = appsync.create_graphql_api(
        name=name, authenticationType="API_KEY", tags={"sim2real-behav": name}
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _safe_delete_graphql_api(appsync, api_id))
    ctx.on_cleanup(lambda: _safe_delete_api_cache(appsync, api_id))

    def _create():
        try:
            appsync.create_api_cache(
                apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
            )
            return ("ok", None, None)
        except Exception as exc:  # noqa: BLE001 - we classify below
            from botocore.exceptions import ClientError

            if isinstance(exc, ClientError):
                return ("error", exc.response["Error"]["Code"], exc.response["Error"].get("Message", ""))
            return ("error", repr(exc), "")

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _create(), range(2)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]

    assert len(successes) == 1, f"expected exactly one winner among racing CreateApiCache calls, got {results}"
    assert len(failures) == 1, f"expected exactly one loser among racing CreateApiCache calls, got {results}"
    assert failures[0][1] == "BadRequestException", (
        f"expected the losing racer to get BadRequestException, got {failures[0][1]!r}"
    )
    assert failures[0][2] == "The API has already enabled caching.", (
        f"expected the losing racer's BadRequestException message to be exactly "
        f"'The API has already enabled caching.', got {failures[0][2]!r}"
    )

    # The winning create should still be observable and progress toward AVAILABLE/FAILED. Real AWS
    # cache provisioning (an ElastiCache cluster behind the scenes) has no documented SLA; the
    # declared 900s bound is what pushes this suite's own wall-clock ceiling high enough to fit it.
    # If real AWS is still provisioning when the budget elapses, this still FAILS -- skipping is
    # not a legal outcome on any target.
    cache = _poll_until(
        lambda: appsync.get_api_cache(apiId=api_id)["apiCache"],
        lambda c: c["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=900,
        interval_s=10,
    )
    if cache is None or cache["status"] != "AVAILABLE":
        raise AssertionError(
            f"ApiCache did not reach AVAILABLE within budget (status="
            f"{cache.get('status') if cache else None!r}); cannot exercise the winner-provisions path",
        )


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


def _poll_until(probe, predicate, *, timeout_s=900, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        result = probe()
        if predicate(result):
            return result
        time.sleep(interval_s)
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
