"""list-scopes-reflects-created-scope."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-scopes-reflects-created-scope"
GROUP = "state"
SERVICES = ["networkflowmonitor"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:networkflowmonitor-scope")
def run(ctx) -> None:
    """ListScopes lists the check's scope with a matching scopeArn; the scope is created, or the
    Region's one existing scope (DeleteScope does not free the slot) is reactivated with UpdateScope."""
    nfm = ctx.client("networkflowmonitor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    target = {"targetIdentifier": {"targetId": {"accountId": account_id}, "targetType": "ACCOUNT"}, "region": ctx.region}
    scope = _acquire_scope(ctx, nfm, target)
    scope_id, scope_arn = scope["scopeId"], scope["scopeArn"]

    found = None
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = nfm.list_scopes(**kwargs)
        for s in resp["scopes"]:
            if s["scopeId"] == scope_id:
                found = s
                break
        next_token = resp.get("nextToken")
        if found is not None or not next_token:
            break

    assert found is not None, f"scope {scope_id} not found via ListScopes"
    assert found["scopeArn"] == scope_arn, f"expected scopeArn {scope_arn!r}, ListScopes returned {found['scopeArn']!r}"


def _acquire_scope(ctx, nfm, target: dict, timeout_s: float = 600.0) -> dict:
    """Acquire the account's singleton NetworkFlowMonitor scope, reactivating it via UpdateScope if it
    is deactivated (NetworkFlowMonitor allows only one scope per
    account/Region and DeleteScope does not free that slot)."""
    try:
        resp = nfm.create_scope(targets=[target], tags={"sim2real-owner": "behavioral-suite"})
        scope_id, scope_arn = resp["scopeId"], resp["scopeArn"]
        ctx.on_cleanup(lambda: _delete_scope_and_wait(nfm, scope_id))
    except ClientError as err:
        if err.response["Error"]["Code"] != "ServiceQuotaExceededException":
            raise
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
        scope_arn = nfm.get_scope(scopeId=scope_id)["scopeArn"]
    _wait_scope_succeeded(nfm, scope_id, timeout_s=timeout_s)
    return {"scopeId": scope_id, "scopeArn": scope_arn}


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


def _wait_scope_succeeded(nfm, scope_id: str, timeout_s: float = 600.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = nfm.get_scope(scopeId=scope_id)["status"]
        if last in ("SUCCEEDED", "FAILED"):
            break
        time.sleep(interval_s)
    else:
        raise AssertionError(f"scope {scope_id} did not settle within {timeout_s}s; last={last!r}")
    assert last == "SUCCEEDED", f"expected scope {scope_id} to settle SUCCEEDED, got {last!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


