"""monitor-tags-set-at-creation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "monitor-tags-set-at-creation"
GROUP = "tags"
SERVICES = ["networkflowmonitor"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:networkflowmonitor-scope")
def run(ctx) -> None:
    """Tags passed to CreateMonitor are returned in the response and visible via GetMonitor and
    ListTagsForResource."""
    nfm = ctx.client("networkflowmonitor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    expected_tags = {"sim2real-owner": "behavioral-suite"}

    scope = _create_scope(ctx, nfm, [_target(account_id, ctx.region)])
    _wait_scope_succeeded(nfm, scope["scopeId"])

    monitor_name = ctx.unique_name("sim2real-nfm-mon-")
    created = nfm.create_monitor(
        monitorName=monitor_name,
        localResources=[{"type": "AWS::Region", "identifier": ctx.region}],
        scopeArn=scope["scopeArn"],
        tags=expected_tags,
    )
    ctx.on_cleanup(lambda: _safe_delete_monitor(nfm, monitor_name))
    assert created["tags"] == expected_tags, f"create response tags: expected {expected_tags}, got {created['tags']}"

    fetched = nfm.get_monitor(monitorName=monitor_name)["tags"]
    assert fetched == expected_tags, f"GetMonitor tags: expected {expected_tags}, got {fetched}"

    listed = nfm.list_tags_for_resource(resourceArn=created["monitorArn"])["tags"]
    assert listed == expected_tags, f"ListTagsForResource tags: expected {expected_tags}, got {listed}"


def _target(account_id: str, region: str) -> dict:
    return {"targetIdentifier": {"targetId": {"accountId": account_id}, "targetType": "ACCOUNT"}, "region": region}


def _create_scope(ctx, nfm, targets: list) -> dict:
    """Acquire a scope to attach a monitor to. NetworkFlowMonitor allows only one scope per
    account/Region, so if one already exists (created by another check) it is reused."""
    try:
        resp = nfm.create_scope(targets=targets)
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
    assert final == "SUCCEEDED", f"scope {scope_id} settled at {final!r}, not SUCCEEDED"


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
