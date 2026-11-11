"""scope-lifecycle-in-progress-to-succeeded."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scope-lifecycle-in-progress-to-succeeded"
GROUP = "state"
SERVICES = ["networkflowmonitor"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:networkflowmonitor-scope")
def run(ctx) -> None:
    """CreateScope answers IN_PROGRESS or SUCCEEDED and the scope settles to SUCCEEDED with the
    requested target and the same scopeArn; the Region's one existing scope (DeleteScope does not
    free the slot) is reactivated with UpdateScope instead."""
    nfm = ctx.client("networkflowmonitor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    target = {"targetIdentifier": {"targetId": {"accountId": account_id}, "targetType": "ACCOUNT"}, "region": ctx.region}
    scope = _acquire_scope(ctx, nfm, target)
    if scope["created"]:
        assert scope["initial_status"] in ("IN_PROGRESS", "SUCCEEDED"), (
            f"expected CreateScope status IN_PROGRESS or SUCCEEDED, got {scope['initial_status']!r}"
        )

    final = _poll_until(
        lambda: nfm.get_scope(scopeId=scope["scopeId"]),
        lambda s: s["status"] in ("SUCCEEDED", "FAILED"),
        timeout_s=600.0,
        interval_s=5.0,
    )
    assert final["status"] == "SUCCEEDED", f"expected scope to settle SUCCEEDED, got {final['status']!r}"
    assert final["targets"] == [target], f"expected targets {[target]!r}, got {final['targets']!r}"
    assert final["scopeArn"] == scope["scopeArn"], (
        f"expected scopeArn {scope['scopeArn']!r}, got {final['scopeArn']!r}"
    )


def _acquire_scope(ctx, nfm, target: dict, timeout_s: float = 1500.0) -> dict:
    """Acquire the account's singleton NetworkFlowMonitor scope, reactivating it via UpdateScope if it
    is deactivated (NetworkFlowMonitor allows only one scope per
    account/Region and DeleteScope does not free that slot)."""
    created = False
    initial_status = None
    try:
        resp = nfm.create_scope(targets=[target], tags={"sim2real-owner": "behavioral-suite"})
        scope_id, scope_arn = resp["scopeId"], resp["scopeArn"]
        initial_status = resp["status"]
        created = True
        ctx.on_cleanup(lambda: _delete_scope_and_wait(nfm, scope_id))
    except ClientError as err:
        if err.response["Error"]["Code"] != "ServiceQuotaExceededException":
            raise
        # The quota refusal means the account's one scope slot is taken, and DeleteScope never frees
        # it, so no check can create its own; this one reactivates the slot's scope and puts back the
        # deactivated state it found.
        existing = nfm.list_scopes().get("scopes", [])
        assert existing, "ServiceQuotaExceededException but no existing scope found via ListScopes"
        scope_id = existing[0]["scopeId"]
        status = nfm.get_scope(scopeId=scope_id)["status"]
        if status in ("DEACTIVATED", "DEACTIVATING"):
            try:
                nfm.update_scope(scopeId=scope_id, resourcesToAdd=[target])
            except ClientError as err2:
                if err2.response["Error"]["Code"] not in ("ConflictException", "ValidationException"):
                    raise
            ctx.on_cleanup(lambda: _delete_scope_and_wait(nfm, scope_id))
        scope_arn = nfm.get_scope(scopeId=scope_id)["scopeArn"]
    _wait_scope_succeeded(nfm, scope_id, timeout_s=timeout_s)
    return {"scopeId": scope_id, "scopeArn": scope_arn, "created": created, "initial_status": initial_status}


def _delete_scope_and_wait(nfm, scope_id: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> None:
    try:
        nfm.delete_scope(scopeId=scope_id)
    except ClientError as err:
        if err.response["Error"]["Code"] in ("ResourceNotFoundException", "ConflictException", "ValidationException"):
            return
        raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = nfm.get_scope(scopeId=scope_id)["status"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if status == "DEACTIVATED":
            return
        time.sleep(interval_s)
    raise AssertionError(f"scope {scope_id} did not fully deactivate within {timeout_s}s")


def _wait_scope_succeeded(nfm, scope_id: str, timeout_s: float = 600.0) -> None:
    final = _poll_until(
        lambda: nfm.get_scope(scopeId=scope_id)["status"],
        lambda s: s in ("SUCCEEDED", "FAILED"),
        timeout_s=timeout_s,
        interval_s=5.0,
    )
    assert final == "SUCCEEDED", f"expected scope {scope_id} to settle SUCCEEDED, got {final!r}"


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

