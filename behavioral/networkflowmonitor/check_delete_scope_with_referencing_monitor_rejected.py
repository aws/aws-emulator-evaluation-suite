"""delete-scope-with-referencing-monitor-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-scope-with-referencing-monitor-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkflowmonitor"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:networkflowmonitor-scope")
def run(ctx) -> None:
    """DeleteScope on a settled scope still referenced by a monitor is rejected with ValidationException
    and the scope stays SUCCEEDED; deleting the monitor first then lets DeleteScope succeed and remove
    the scope (positive control)."""
    nfm = ctx.client("networkflowmonitor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # The account's singleton scope is shared with sibling checks that update it, so it can sit
    # IN_PROGRESS for many minutes; the wait leaves the rest of the check its own time.
    scope_wait = max(1.0, min(1200.0, (ctx.time_left() or 1200.0) - 300.0))
    scope_deadline = time.monotonic() + scope_wait
    scope = _acquire_scope(ctx, nfm, _target(account_id, ctx.region), timeout_s=scope_wait)
    _wait_scope_succeeded(nfm, scope["scopeId"], timeout_s=max(1.0, scope_deadline - time.monotonic()))

    monitor_name = ctx.unique_name("sim2real-nfm-refmon-")
    nfm.create_monitor(
        monitorName=monitor_name,
        localResources=[{"type": "AWS::Region", "identifier": ctx.region}],
        scopeArn=scope["scopeArn"],
        tags={"sim2real-owner": "behavioral-suite"},
    )
    ctx.on_cleanup(lambda: _safe_delete_monitor(nfm, monitor_name))
    _wait_monitor_active(nfm, monitor_name)

    # A scope still being mutated answers ConflictException; settle it first so the refusal graded is
    # the referencing monitor's.
    _wait_scope_succeeded(nfm, scope["scopeId"], timeout_s=40.0)
    rejection = _expect_rejected(lambda: nfm.delete_scope(scopeId=scope["scopeId"]))
    assert rejection == (
        "ValidationException", "Scope can't be deleted as there's monitors associated with it"
    ), (
        f"expected DeleteScope on a settled scope with a referencing monitor to be rejected with "
        f"ValidationException, got {rejection!r}"
    )

    # Effect absent: the scope is still SUCCEEDED, not DEACTIVATING/DEACTIVATED.
    unaffected = nfm.get_scope(scopeId=scope["scopeId"])
    assert unaffected["status"] == "SUCCEEDED", (
        f"expected the rejected DeleteScope to leave the scope status unchanged at SUCCEEDED, "
        f"got {unaffected['status']!r}"
    )

    # Positive control: delete the referencing monitor first, then DeleteScope succeeds. Since this
    # account has only one (singleton) scope, also clear any other stray monitors left by other checks
    # that would otherwise still block DeleteScope.
    nfm.delete_monitor(monitorName=monitor_name)
    _poll_until(
        lambda: _monitor_gone(nfm, monitor_name),
        lambda gone: gone,
        timeout_s=600.0,
        interval_s=10.0,
    )
    _delete_all_monitors(nfm)

    nfm.delete_scope(scopeId=scope["scopeId"])
    # An unreferenced scope's DeleteScope removes it: GetScope then answers ResourceNotFoundException.
    final = _poll_until(
        lambda: _scope_status_or_removed(nfm, scope["scopeId"]),
        lambda s: s in ("DEACTIVATED", "FAILED", "<REMOVED>"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert final == "<REMOVED>", (
        f"expected DeleteScope to succeed once the referencing monitor is gone and remove the "
        f"scope (GetScope -> ResourceNotFoundException), got {final!r}"
    )


def _target(account_id: str, region: str) -> dict:
    return {"targetIdentifier": {"targetId": {"accountId": account_id}, "targetType": "ACCOUNT"}, "region": region}


def _acquire_scope(ctx, nfm, target: dict, timeout_s: float = 600.0) -> dict:
    """Acquire the account's singleton NetworkFlowMonitor scope, reactivating it via UpdateScope if it
    was previously deactivated by another check (NetworkFlowMonitor allows only one scope per
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


def _safe_delete_monitor(nfm, monitor_name: str) -> None:
    try:
        nfm.delete_monitor(monitorName=monitor_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_all_monitors(nfm, timeout_s: float = 300.0, interval_s: float = 10.0) -> None:
    names = []
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = nfm.list_monitors(**kwargs)
        names.extend(m["monitorName"] for m in resp["monitors"])
        next_token = resp.get("nextToken")
        if not next_token:
            break
    for name in names:
        try:
            nfm.delete_monitor(monitorName=name)
        except ClientError as err:
            if err.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
    deadline = time.monotonic() + timeout_s
    for name in names:
        while time.monotonic() < deadline:
            try:
                nfm.get_monitor(monitorName=name)
            except ClientError as err:
                if err.response["Error"]["Code"] == "ResourceNotFoundException":
                    break
                raise
            time.sleep(interval_s)
        else:
            raise AssertionError(f"monitor {name} was not removed within {timeout_s}s")


def _wait_scope_succeeded(nfm, scope_id: str, timeout_s: float = 600.0) -> None:
    final = _poll_until(
        lambda: nfm.get_scope(scopeId=scope_id)["status"],
        lambda s: s in ("SUCCEEDED", "FAILED"),
        timeout_s=timeout_s,
        interval_s=5.0,
    )
    assert final == "SUCCEEDED", f"expected scope {scope_id} to reach SUCCEEDED, got {final!r}"


def _wait_monitor_active(nfm, monitor_name: str, timeout_s: float = 240.0) -> None:
    final = _poll_until(
        lambda: nfm.get_monitor(monitorName=monitor_name)["monitorStatus"],
        lambda s: s in ("ACTIVE", "ERROR"),
        timeout_s=timeout_s,
        interval_s=10.0,
    )
    assert final == "ACTIVE", f"expected monitor {monitor_name} to reach ACTIVE, got {final!r}"


def _monitor_gone(nfm, monitor_name: str) -> bool:
    """True once GetMonitor answers ResourceNotFoundException; any other error raises."""
    try:
        nfm.get_monitor(monitorName=monitor_name)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        raise
    return False


def _expect_rejected(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises immediately."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _scope_status_or_removed(nfm, scope_id: str) -> str:
    """GetScope's status, or ``<REMOVED>`` once GetScope answers ResourceNotFoundException."""
    try:
        return nfm.get_scope(scopeId=scope_id)["status"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return "<REMOVED>"
        raise


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
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
