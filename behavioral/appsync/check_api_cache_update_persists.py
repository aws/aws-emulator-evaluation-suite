"""api-cache-update-persists."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "api-cache-update-persists"
GROUP = "state-machine"
SERVICES = ["appsync"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateApiCache changes ttl/type/behavior; GetApiCache reflects it once AVAILABLE again."""
    # Real ApiCache provisioning (an ElastiCache cluster behind the scenes) has no documented SLA.
    # Creating a SMALL cache usually reaches AVAILABLE within minutes;
    # THIS check's UpdateApiCache changes ttl AND apiCachingBehavior AND type=SMALL->MEDIUM, a
    # cache resize, which AWS can keep MODIFYING past 600s, so the update wait is the long one.
    _create_wait_s = 450.0
    _update_wait_s = 1000.0
    _delete_wait_s = 300.0

    appsync = ctx.client("appsync")
    api_id = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-appsync-cache-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK, "sim2real:managed": "true"},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _delete_graphql_api_quiet(appsync, api_id))

    created = appsync.create_api_cache(
        apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )["apiCache"]
    ctx.on_cleanup(lambda: _delete_api_cache_quiet(appsync, api_id))
    assert created["ttl"] == 300
    assert created["apiCachingBehavior"] == "FULL_REQUEST_CACHING"
    assert created["type"] == "SMALL"

    def _probe_cache():
        return appsync.get_api_cache(apiId=api_id)["apiCache"]

    available = _poll_until(
        _probe_cache,
        lambda c: c["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=_create_wait_s,
        interval_s=10,
    )
    if available["status"] != "AVAILABLE":
        raise AssertionError(
            f"ApiCache creation did not reach AVAILABLE within budget (status={available['status']!r})",
        )

    appsync.update_api_cache(
        apiId=api_id, ttl=600, apiCachingBehavior="PER_RESOLVER_CACHING", type="MEDIUM"
    )

    updated = _poll_until(
        _probe_cache,
        lambda c: c["status"] in ("AVAILABLE", "FAILED"),
        timeout_s=_update_wait_s,
        interval_s=5,
    )
    if updated["status"] != "AVAILABLE":
        raise AssertionError(
            f"ApiCache update did not reach AVAILABLE within budget (status={updated['status']!r})",
        )
    assert updated["ttl"] == 600, "UpdateApiCache ttl change did not persist"
    assert updated["apiCachingBehavior"] == "PER_RESOLVER_CACHING", (
        "UpdateApiCache apiCachingBehavior change did not persist"
    )
    assert updated["type"] == "MEDIUM", "UpdateApiCache type change did not persist"

    appsync.delete_api_cache(apiId=api_id)

    def _probe_gone():
        try:
            appsync.get_api_cache(apiId=api_id)
            return ("still-present", None)
        except Exception as exc:  # noqa: BLE001
            return _error_from_exc(exc)

    gone = _poll_until(
        _probe_gone, lambda c: c[0] == "NotFoundException", timeout_s=_delete_wait_s, interval_s=5
    )
    assert gone == (
        "NotFoundException",
        "Unable to get the cache as it has been deleted, please re-create the cache.",
    ), f"GetApiCache on a deleted cache should 404 with NotFoundException, got {gone!r}"

    # A mutation on the now-dead cache must also fail with the same specific not-found
    # code, not silently no-op or succeed against a resurrected cache.
    flush_result = (None, None)
    try:
        appsync.flush_api_cache(apiId=api_id)
    except Exception as exc:  # noqa: BLE001
        flush_result = _error_from_exc(exc)
    assert flush_result == (
        "NotFoundException",
        "Unable to flush the cache as it has been deleted, please re-create the cache.",
    ), f"FlushApiCache on a deleted cache should 404 with NotFoundException, got {flush_result!r}"


# ===== self-contained helpers =====
def _error_code_from_exc(exc: Exception) -> str | None:
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        return resp.get("Error", {}).get("Code")
    return None


def _error_from_exc(exc: Exception) -> tuple[str | None, str | None]:
    resp = getattr(exc, "response", None)
    if isinstance(resp, dict):
        err = resp.get("Error", {})
        return err.get("Code"), err.get("Message")
    return None, None


def _delete_graphql_api_quiet(appsync: Any, api_id: str) -> None:
    try:
        appsync.delete_graphql_api(apiId=api_id)
    except Exception as exc:  # noqa: BLE001
        if _error_code_from_exc(exc) != "NotFoundException":
            raise


def _delete_api_cache_quiet(appsync: Any, api_id: str, settle_s: float = 780.0) -> None:
    """Delete the cache once it leaves CREATING/MODIFYING: AWS refuses DeleteApiCache on a cache
    mid-transition with BadRequestException."""
    deadline = time.monotonic() + settle_s
    while time.monotonic() < deadline:
        try:
            status = appsync.get_api_cache(apiId=api_id)["apiCache"]["status"]
        except Exception as exc:  # noqa: BLE001
            if _error_code_from_exc(exc) == "NotFoundException":
                return
            raise
        if status not in ("CREATING", "MODIFYING"):
            break
        time.sleep(10)
    try:
        appsync.delete_api_cache(apiId=api_id)
    except Exception as exc:  # noqa: BLE001
        if _error_code_from_exc(exc) != "NotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    # NOTE: on timeout this returns the last observed value instead of raising. Callers
    # polling for a terminal provisioning state (AVAILABLE/FAILED) explicitly turn "still not
    # terminal" into a raised AssertionError themselves -- a real, honest
    # fail, never a skip; the final post-delete poll still asserts on the returned value itself
    # (NotFoundException), so no assertion is weakened here.
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            return result
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
