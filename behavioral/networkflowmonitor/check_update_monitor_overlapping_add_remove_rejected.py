"""update-monitor-overlapping-add-remove-rejected."""
from __future__ import annotations

import re

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-monitor-overlapping-add-remove-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkflowmonitor"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:networkflowmonitor-scope")
def run(ctx) -> None:
    """UpdateMonitor that adds and removes the same local resource in one call is rejected with
    ValidationException and the monitor's resources are left unchanged; an unambiguous remove of a
    different (remote) resource still succeeds (positive control)."""
    nfm = ctx.client("networkflowmonitor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    scope = _create_scope(ctx, nfm, [_target(account_id, ctx.region)])
    _wait_scope_succeeded(nfm, scope["scopeId"])

    local_resource = {"type": "AWS::Region", "identifier": ctx.region}
    remote_resource = {"type": "AWS::AWSService", "identifier": "S3"}
    monitor_name = ctx.unique_name("sim2real-nfm-overlap-")
    nfm.create_monitor(
        monitorName=monitor_name,
        localResources=[local_resource],
        remoteResources=[remote_resource],
        scopeArn=scope["scopeArn"],
        tags={"sim2real-owner": "behavioral-suite"},
    )
    ctx.on_cleanup(lambda: _safe_delete_monitor(nfm, monitor_name))
    _wait_monitor_active(nfm, monitor_name)

    code, message = _error_code(
        lambda: nfm.update_monitor(
            monitorName=monitor_name,
            localResourcesToAdd=[local_resource],
            localResourcesToRemove=[local_resource],
        )
    )
    assert code == "ValidationException", f"expected ValidationException for overlapping add/remove, got {code!r}"
    expected = "invalid input -> (detected overlap between add/remove resources)"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the resource lists are unchanged.
    unaffected = nfm.get_monitor(monitorName=monitor_name)
    assert unaffected["localResources"] == [local_resource], (
        f"localResources changed despite rejected update: {unaffected['localResources']!r}"
    )
    assert unaffected["remoteResources"] == [remote_resource], (
        f"remoteResources changed despite rejected update: {unaffected['remoteResources']!r}"
    )

    # Positive control: an unambiguous remove (no overlap) succeeds.
    nfm.update_monitor(monitorName=monitor_name, remoteResourcesToRemove=[remote_resource])
    final = _poll_until(
        lambda: nfm.get_monitor(monitorName=monitor_name),
        lambda m: m["monitorStatus"] in ("ACTIVE", "ERROR"),
        timeout_s=240.0,
        interval_s=10.0,
    )
    assert final["monitorStatus"] == "ACTIVE", f"expected ACTIVE after unambiguous remove, got {final['monitorStatus']!r}"
    assert final["remoteResources"] == [], f"expected remoteResources cleared, got {final['remoteResources']!r}"


def _target(account_id: str, region: str) -> dict:
    return {"targetIdentifier": {"targetId": {"accountId": account_id}, "targetType": "ACCOUNT"}, "region": region}


def _create_scope(ctx, nfm, targets: list) -> dict:
    """Acquire a scope to attach a monitor to. NetworkFlowMonitor allows only one scope per
    account/Region, so if one already exists (created by another check) it is reused."""
    try:
        resp = nfm.create_scope(targets=targets, tags={"sim2real-owner": "behavioral-suite"})
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


def _wait_scope_succeeded(nfm, scope_id: str, timeout_s: float = 600.0) -> None:
    final = _poll_until(
        lambda: nfm.get_scope(scopeId=scope_id)["status"],
        lambda s: s in ("SUCCEEDED", "FAILED"),
        timeout_s=timeout_s,
        interval_s=5.0,
    )
    assert final == "SUCCEEDED", f"scope {scope_id} did not reach SUCCEEDED, got {final!r}"


def _wait_monitor_active(nfm, monitor_name: str, timeout_s: float = 240.0) -> None:
    final = _poll_until(
        lambda: nfm.get_monitor(monitorName=monitor_name)["monitorStatus"],
        lambda s: s in ("ACTIVE", "ERROR"),
        timeout_s=timeout_s,
        interval_s=10.0,
    )
    assert final == "ACTIVE", f"monitor {monitor_name} did not reach ACTIVE, got {final!r}"


def _error_code(fn):
    """Call fn() and return its ClientError code. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), _without_request_suffix(error.get("Message"))
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


_REQUEST_SUFFIX = re.compile(
    r" \(Service: [A-Za-z0-9]+, Status Code: \d+, Request ID: [0-9a-fA-F-]+\)"
    r"( \(SDK Attempt Count: \d+\))?$"
)


def _without_request_suffix(message: str) -> str:
    """The message minus its per-request "(Service: ..., Request ID: ...) (SDK Attempt Count: n)"
    suffix, which is the only part that differs between calls."""
    return _REQUEST_SUFFIX.sub("", message or "")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
