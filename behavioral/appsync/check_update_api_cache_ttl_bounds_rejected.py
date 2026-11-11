"""update-api-cache-ttl-bounds-rejected."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "update-api-cache-ttl-bounds-rejected"
GROUP = "overly-permissive"
SERVICES = ["appsync"]

# Real AWS takes several minutes to provision a SMALL cache, so each settle-wait is bounded at
# 900s; the runner derives its per-check budget from these bounds.
_CACHE_TIMEOUT_S = 900.0
_CACHE_POLL_S = 5.0


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateApiCache and UpdateApiCache reject out-of-range ttl (outside 1-3600s) with
    BadRequestException and leave no effect, while still accepting an in-range ttl --
    otherwise "rejects out-of-range" is indistinguishable from "rejects every call"."""
    appsync = ctx.client("appsync")

    api_id = appsync.create_graphql_api(
        name=ctx.unique_name("sim2real-cachettl-api-"),
        authenticationType="API_KEY",
        tags={"sim2real": CHECK},
    )["graphqlApi"]["apiId"]
    ctx.on_cleanup(lambda: _safe_delete_graphql_api(appsync, api_id))

    # CreateApiCache itself must reject an out-of-range ttl (upper bound is documented as 3600s).
    create_code, create_msg = _error(
        lambda: appsync.create_api_cache(
            apiId=api_id, ttl=999999, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
        )
    )
    assert create_code == "BadRequestException", (
        f"CreateApiCache with ttl=999999 should be rejected with BadRequestException, got {create_code!r}"
    )
    assert create_msg == "TTL value cannot be smaller than 1 second and larger than 3600 seconds.", f"unexpected message: {create_msg!r}"

    create_code_zero, create_code_zero_msg = _error(
        lambda: appsync.create_api_cache(
            apiId=api_id, ttl=0, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
        )
    )
    assert create_code_zero == "BadRequestException", (
        f"CreateApiCache with ttl=0 should be rejected with BadRequestException, got {create_code_zero!r}"
    )
    assert create_code_zero_msg == "TTL value cannot be smaller than 1 second and larger than 3600 seconds.", f"unexpected message: {create_code_zero_msg!r}"

    # Effect-absent: neither rejected CreateApiCache call left a resource behind.
    no_cache_code, no_cache_msg = _error(lambda: appsync.get_api_cache(apiId=api_id))
    assert no_cache_code == "NotFoundException", (
        f"a rejected CreateApiCache call left an ApiCache behind: GetApiCache returned "
        f"{no_cache_code!r} instead of NotFoundException"
    )
    assert no_cache_msg == "Unable to get the cache as it doesn't exist, please create the cache first.", f"unexpected message: {no_cache_msg!r}"

    # Now create a valid cache and confirm UpdateApiCache enforces the same bounds.
    appsync.create_api_cache(
        apiId=api_id, ttl=300, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )
    ctx.on_cleanup(lambda: _safe_delete_api_cache(appsync, api_id))

    status = _poll_cache_status(appsync, api_id, {"AVAILABLE", "FAILED"})
    if status != "AVAILABLE":
        raise AssertionError(
            f"ApiCache did not reach AVAILABLE in time (status={status})",
        )

    # Positive control: UpdateApiCache itself must succeed on a valid ttl. Without this, the
    # negatives below cannot distinguish "rejects out-of-range ttl" from "rejects every
    # UpdateApiCache call".
    appsync.update_api_cache(
        apiId=api_id, ttl=600, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
    )
    settled = _poll_cache_status(appsync, api_id, {"AVAILABLE", "FAILED"}, timeout_s=900)
    if settled != "AVAILABLE":
        raise AssertionError(
            f"ApiCache did not return to AVAILABLE after a valid UpdateApiCache (status={settled})",
        )
    after_valid_update = appsync.get_api_cache(apiId=api_id)["apiCache"]
    assert after_valid_update["ttl"] == 600, (
        f"UpdateApiCache with a valid ttl=600 should have applied, got ttl={after_valid_update['ttl']}"
    )

    update_code_high, update_code_high_msg = _error(
        lambda: appsync.update_api_cache(
            apiId=api_id, ttl=3601, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
        )
    )
    assert update_code_high == "BadRequestException", (
        f"UpdateApiCache with ttl=3601 should be rejected with BadRequestException, got {update_code_high!r}"
    )
    assert update_code_high_msg == "TTL value cannot be smaller than 1 second and larger than 3600 seconds.", f"unexpected message: {update_code_high_msg!r}"

    update_code_low, update_code_low_msg = _error(
        lambda: appsync.update_api_cache(
            apiId=api_id, ttl=0, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
        )
    )
    assert update_code_low == "BadRequestException", (
        f"UpdateApiCache with ttl=0 should be rejected with BadRequestException, got {update_code_low!r}"
    )
    assert update_code_low_msg == "TTL value cannot be smaller than 1 second and larger than 3600 seconds.", f"unexpected message: {update_code_low_msg!r}"

    negative_ttl_code, negative_ttl_msg = _error(
        lambda: appsync.update_api_cache(
            apiId=api_id, ttl=-5, apiCachingBehavior="FULL_REQUEST_CACHING", type="SMALL"
        )
    )
    assert negative_ttl_code == "BadRequestException", (
        f"UpdateApiCache with ttl=-5 should be rejected with BadRequestException, got {negative_ttl_code!r}"
    )
    assert negative_ttl_msg == "TTL value cannot be smaller than 1 second and larger than 3600 seconds.", f"unexpected message: {negative_ttl_msg!r}"

    # The cache resource must remain unaffected (still AVAILABLE, ttl unchanged from the last
    # successful update) after the rejected updates -- a bad request must not partially mutate
    # state.
    unaffected = appsync.get_api_cache(apiId=api_id)["apiCache"]
    assert unaffected["ttl"] == 600, "rejected UpdateApiCache calls must not change the stored ttl"
    assert unaffected["status"] == "AVAILABLE", "rejected UpdateApiCache calls must not change status"


def _error(fn: Any) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises -- an
    over-permissive target ACCEPTING a call this check expects rejected is the strongest signal
    available and must not be reduced to a plain code mismatch."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if resp:
            err = resp.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_cache_status(appsync: Any, api_id: str, terminal: set[str], timeout_s: float = _CACHE_TIMEOUT_S) -> str:
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
    while True:
        try:
            appsync.delete_api_cache(apiId=api_id)
            return
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code == "ConcurrentModificationException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise


def _safe_delete_graphql_api(appsync: Any, api_id: str) -> None:
    deadline = time.monotonic() + 90.0
    while True:
        try:
            appsync.delete_graphql_api(apiId=api_id)
            return
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code == "NotFoundException":
                return
            if code == "ConcurrentModificationException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
