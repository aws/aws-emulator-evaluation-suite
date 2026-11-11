"""start-query-invalid-time-range-rejected."""
from __future__ import annotations

import datetime as dt
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-query-invalid-time-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkflowmonitor"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control", "resource:account-singleton:networkflowmonitor-scope")
def run(ctx) -> None:
    """StartQueryMonitorTopContributors with startTime after endTime is rejected with ValidationException
    (no queryId is ever produced), while a valid time range still starts a query successfully."""
    nfm = ctx.client("networkflowmonitor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    scope = _create_scope(ctx, nfm, [_target(account_id, ctx.region)])
    _wait_scope_succeeded(nfm, scope["scopeId"])

    monitor_name = ctx.unique_name("sim2real-nfm-badrange-")
    nfm.create_monitor(
        monitorName=monitor_name,
        localResources=[{"type": "AWS::Region", "identifier": ctx.region}],
        scopeArn=scope["scopeArn"],
        tags={"sim2real-owner": "behavioral-suite"},
    )
    ctx.on_cleanup(lambda: _safe_delete_monitor(nfm, monitor_name))
    _wait_monitor_active(nfm, monitor_name)

    now = dt.datetime.now(dt.timezone.utc)
    error = _expect_error(
        lambda: nfm.start_query_monitor_top_contributors(
            monitorName=monitor_name,
            startTime=now,
            endTime=now - dt.timedelta(hours=1),
            metricName="DATA_TRANSFERRED",
            destinationCategory="UNCLASSIFIED",
        )
    )
    assert error["Code"] == "ValidationException", (
        f"expected ValidationException for startTime after endTime, got {error!r}"
    )
    assert error["Message"] == "EndTime cannot be before StartTime", (
        f"expected the exact refusal message for startTime after endTime, got {error.get('Message')!r}"
    )

    # Positive control: the identical call shape with a valid time range must still start a
    # query that actually runs to completion -- otherwise "rejects a bad range" would be
    # indistinguishable from "rejects every StartQueryMonitorTopContributors call".
    started = nfm.start_query_monitor_top_contributors(
        monitorName=monitor_name,
        startTime=now - dt.timedelta(hours=1),
        endTime=now,
        metricName="DATA_TRANSFERRED",
        destinationCategory="UNCLASSIFIED",
    )
    query_id = started["queryId"]
    assert query_id, f"StartQueryMonitorTopContributors returned no queryId: {started!r}"

    final_status = _poll_until(
        lambda: nfm.get_query_status_monitor_top_contributors(monitorName=monitor_name, queryId=query_id)["status"],
        lambda s: s in ("SUCCEEDED", "FAILED", "CANCELED"),
        timeout_s=600.0,
        interval_s=5.0,
    )
    assert final_status == "SUCCEEDED", f"expected query {query_id} to reach SUCCEEDED, got {final_status!r}"


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
    assert final == "SUCCEEDED", f"expected scope {scope_id} to reach SUCCEEDED, got {final!r}"


def _wait_monitor_active(nfm, monitor_name: str, timeout_s: float = 240.0) -> None:
    final = _poll_until(
        lambda: nfm.get_monitor(monitorName=monitor_name)["monitorStatus"],
        lambda s: s in ("ACTIVE", "ERROR"),
        timeout_s=timeout_s,
        interval_s=10.0,
    )
    assert final == "ACTIVE", f"expected monitor {monitor_name} to reach ACTIVE, got {final!r}"


def _expect_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
