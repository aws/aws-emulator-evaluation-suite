"""monitor-lifecycle-pending-to-active."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "monitor-lifecycle-pending-to-active"
GROUP = "state"
SERVICES = ["networkflowmonitor"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:networkflowmonitor-scope")
def run(ctx) -> None:
    """CreateMonitor starts PENDING/ACTIVE and settles to ACTIVE with the requested resources."""
    nfm = ctx.client("networkflowmonitor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    resource_tags = {"sim2real-owner": "behavioral-suite"}
    scope = _create_scope(ctx, nfm, [_target(account_id, ctx.region)], resource_tags)
    _poll_scope_status(nfm, scope["scopeId"], "SUCCEEDED")

    monitor_name = ctx.unique_name("sim2real-nfm-mon-")
    local_resources = [{"type": "AWS::Region", "identifier": ctx.region}]
    created = nfm.create_monitor(
        monitorName=monitor_name,
        localResources=local_resources,
        scopeArn=scope["scopeArn"],
        tags=resource_tags,
    )
    ctx.on_cleanup(lambda: _safe_delete_monitor(nfm, monitor_name))
    assert created["monitorStatus"] in ("PENDING", "ACTIVE"), (
        f"expected CreateMonitor's own response status to be PENDING or ACTIVE, got {created['monitorStatus']!r}"
    )

    final = _poll_until(
        lambda: nfm.get_monitor(monitorName=monitor_name),
        lambda m: m["monitorStatus"] in ("ACTIVE", "ERROR"),
        timeout_s=240.0,
        interval_s=10.0,
    )
    assert final["monitorStatus"] == "ACTIVE", f"expected monitor to settle to ACTIVE, got {final['monitorStatus']!r}"
    assert final["localResources"] == local_resources, (
        f"expected GetMonitor localResources {local_resources!r}, got {final['localResources']!r}"
    )
    assert final["monitorName"] == monitor_name, f"expected monitorName {monitor_name!r}, got {final['monitorName']!r}"


def _target(account_id: str, region: str) -> dict:
    return {"targetIdentifier": {"targetId": {"accountId": account_id}, "targetType": "ACCOUNT"}, "region": region}


def _create_scope(ctx, nfm, targets: list, resource_tags: dict) -> dict:
    """Acquire a scope to attach a monitor to. NetworkFlowMonitor allows only one scope per
    account/Region, so if one already exists (created by another check) it is reused."""
    try:
        resp = nfm.create_scope(targets=targets, tags=resource_tags)
        scope_id, scope_arn = resp["scopeId"], resp["scopeArn"]
        ctx.on_cleanup(lambda: _delete_scope_and_wait(nfm, scope_id))
    except ClientError as err:
        if err.response["Error"]["Code"] != "ServiceQuotaExceededException":
            raise
        existing = nfm.list_scopes().get("scopes", [])
        assert existing, "ServiceQuotaExceededException but no existing scope found via ListScopes"
        scope_id = existing[0]["scopeId"]
        scope_arn = nfm.get_scope(scopeId=scope_id)["scopeArn"]
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


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _poll_scope_status(nfm, scope_id: str, expected: str, timeout_s: float = 600.0) -> None:
    final = _poll_until(
        lambda: nfm.get_scope(scopeId=scope_id)["status"],
        lambda s: s in ("SUCCEEDED", "FAILED"),
        timeout_s=timeout_s,
        interval_s=5.0,
    )
    assert final == expected, f"expected scope {scope_id} to settle to {expected!r}, got {final!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
