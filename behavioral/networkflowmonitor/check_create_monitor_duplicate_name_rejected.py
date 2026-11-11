"""create-monitor-duplicate-name-rejected."""
from __future__ import annotations

import re

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-monitor-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkflowmonitor"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:networkflowmonitor-scope")
def run(ctx) -> None:
    """CreateMonitor with an already-used monitorName is rejected with ConflictException, leaving the
    original monitor untouched, while a differently-named monitor in the same scope still succeeds."""
    nfm = ctx.client("networkflowmonitor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    tags_ = {"sim2real-owner": "behavioral-suite"}
    scope = _create_scope(ctx, nfm, [_target(account_id, ctx.region)], tags_)
    _wait_scope_succeeded(nfm, scope["scopeId"])

    monitor_name = ctx.unique_name("sim2real-nfm-dup-")
    original_local = [{"type": "AWS::Region", "identifier": ctx.region}]
    nfm.create_monitor(
        monitorName=monitor_name, localResources=original_local, scopeArn=scope["scopeArn"], tags=tags_
    )
    ctx.on_cleanup(lambda: _safe_delete_monitor(nfm, monitor_name))

    code, message = _error_code(
        lambda: nfm.create_monitor(
            monitorName=monitor_name,
            localResources=[{"type": "AWS::AvailabilityZone", "identifier": f"{ctx.region}a"}],
            scopeArn=scope["scopeArn"],
        )
    )
    assert code == "ConflictException", f"expected ConflictException for duplicate monitorName, got {code!r}"
    assert message == "Cannot create a monitor which already exists", (
        f"expected the duplicate-monitor message, got {message!r}"
    )

    # Effect absent: the original monitor's resources were not overwritten by the rejected call.
    unaffected = nfm.get_monitor(monitorName=monitor_name)
    assert unaffected["localResources"] == original_local, (
        f"expected original monitor's localResources to stay {original_local}, "
        f"got {unaffected['localResources']} after the rejected duplicate-name call"
    )

    # Positive control: a distinct monitor name in the same scope still succeeds.
    other_name = ctx.unique_name("sim2real-nfm-dup-ctrl-")
    nfm.create_monitor(monitorName=other_name, localResources=original_local, scopeArn=scope["scopeArn"], tags=tags_)
    ctx.on_cleanup(lambda: _safe_delete_monitor(nfm, other_name))

    # Terminal assertion is an independent read at the destination, not the CreateMonitor echo.
    control_read = nfm.get_monitor(monitorName=other_name)
    assert control_read["localResources"] == original_local, (
        f"expected control monitor {other_name} to be visible via GetMonitor with localResources "
        f"{original_local}, got {control_read['localResources']}"
    )


def _target(account_id: str, region: str) -> dict:
    return {"targetIdentifier": {"targetId": {"accountId": account_id}, "targetType": "ACCOUNT"}, "region": region}


def _create_scope(ctx, nfm, targets: list, tags: dict) -> dict:
    """Acquire a scope to attach a monitor to. NetworkFlowMonitor allows only one scope per
    account/Region, so if one already exists (created by another check) it is reused."""
    try:
        resp = nfm.create_scope(targets=targets, tags=tags)
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
    assert final == "SUCCEEDED", f"expected scope {scope_id} to settle SUCCEEDED, got {final!r}"


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because the target
    accepting a duplicate monitorName is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), _without_request_suffix(error.get("Message"))
    raise AssertionError(f"expected CreateMonitor to reject the duplicate name, but it succeeded and returned {result!r}")


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
