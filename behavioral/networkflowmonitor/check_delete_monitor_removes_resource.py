"""delete-monitor-removes-resource."""
from __future__ import annotations

import re

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-monitor-removes-resource"
GROUP = "state"
SERVICES = ["networkflowmonitor"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:networkflowmonitor-scope")
def run(ctx) -> None:
    """DeleteMonitor drives the monitor through DELETING to full removal (GetMonitor -> NotFound)."""
    nfm = ctx.client("networkflowmonitor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    scope = _create_scope(ctx, nfm, [_target(account_id, ctx.region)])
    _wait_scope_succeeded(nfm, scope["scopeId"])

    monitor_name = ctx.unique_name("sim2real-nfm-mon-")
    nfm.create_monitor(
        monitorName=monitor_name,
        localResources=[{"type": "AWS::Region", "identifier": ctx.region}],
        scopeArn=scope["scopeArn"],
        tags={"sim2real-owner": "behavioral-suite"},
    )
    _wait_monitor_active(nfm, monitor_name)

    nfm.delete_monitor(monitorName=monitor_name)

    def probe():
        try:
            return nfm.get_monitor(monitorName=monitor_name)["monitorStatus"]
        except ClientError as err:
            return err.response["Error"]["Code"]

    final_code = _poll_until(probe, lambda c: c == "ResourceNotFoundException", timeout_s=600.0, interval_s=10.0)
    assert final_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {final_code!r}"
    gone_message = (
        f"Monitor [arn:aws:networkflowmonitor:{ctx.region}:{account_id}:monitor/{monitor_name}] "
        "doesn't exist"
    )

    # Deletion is terminal: a second read still reports NotFound (no resurrection).
    code_again, again_message = _error_code(lambda: nfm.get_monitor(monitorName=monitor_name))
    assert code_again == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code_again!r}"
    assert again_message == gone_message, f"expected message {gone_message!r}, got {again_message!r}"

    # A mutation on the dead id also fails, not just a read: deleting the already-deleted monitor
    # must report the same specific not-found code, never a silent success.
    redelete_code, redelete_message = _error_code(lambda: nfm.delete_monitor(monitorName=monitor_name))
    assert redelete_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {redelete_code!r}"
    assert redelete_message == gone_message, f"expected message {gone_message!r}, got {redelete_message!r}"


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


def _wait_scope_succeeded(nfm, scope_id: str, timeout_s: float = 600.0) -> None:
    final = _poll_until(
        lambda: nfm.get_scope(scopeId=scope_id)["status"],
        lambda s: s in ("SUCCEEDED", "FAILED"),
        timeout_s=timeout_s,
        interval_s=5.0,
    )
    assert final == "SUCCEEDED", f"expected scope status SUCCEEDED, got {final!r}"


def _wait_monitor_active(nfm, monitor_name: str, timeout_s: float = 240.0) -> None:
    final = _poll_until(
        lambda: nfm.get_monitor(monitorName=monitor_name)["monitorStatus"],
        lambda s: s in ("ACTIVE", "ERROR"),
        timeout_s=timeout_s,
        interval_s=10.0,
    )
    assert final == "ACTIVE", f"expected monitor status ACTIVE, got {final!r}"


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, so a target that
    still serves a deleted monitor fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), _without_request_suffix(error.get("Message"))
    raise AssertionError(f"expected the call on the deleted monitor to be rejected, but it succeeded and returned {result!r}")


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
