"""concurrent-create-monitor-same-name-exactly-one-wins."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-monitor-same-name-exactly-one-wins"
GROUP = "concurrency"
SERVICES = ["networkflowmonitor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:networkflowmonitor-scope")
def run(ctx) -> None:
    """Two concurrent CreateMonitor calls with one monitorName: exactly one succeeds, the other gets
    ConflictException, and GetMonitor and ListMonitors show exactly one monitor under that name."""
    nfm = ctx.client("networkflowmonitor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    tags_ = {"sim2real-owner": "behavioral-suite"}
    scope = _create_scope(ctx, nfm, [_target(account_id, ctx.region)], tags_)
    _wait_scope_succeeded(nfm, scope["scopeId"])

    monitor_name = ctx.unique_name("sim2real-nfm-race-")
    ctx.on_cleanup(lambda: _safe_delete_monitor(nfm, monitor_name))

    def attempt():
        try:
            nfm.create_monitor(
                monitorName=monitor_name,
                localResources=[{"type": "AWS::Region", "identifier": ctx.region}],
                scopeArn=scope["scopeArn"],
                tags=tags_,
            )
            return ("ok", None)
        except ClientError as err:
            return ("error", err.response["Error"]["Code"])

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: attempt(), range(2)))

    outcomes = [r[0] for r in results]
    errors = [r[1] for r in results if r[0] == "error"]

    assert outcomes.count("ok") == 1, f"expected exactly one winner, got {results}"
    assert outcomes.count("error") == 1, f"expected exactly one loser, got {results}"
    assert errors == ["ConflictException"], f"expected the loser's error to be ConflictException, got {errors}"

    final = nfm.get_monitor(monitorName=monitor_name)
    assert final["monitorName"] == monitor_name, (
        f"expected GetMonitor({monitor_name!r}) to return the winning monitor, got {final!r}"
    )

    # Independent side-channel: the race must have produced exactly one backing monitor, not just
    # exactly one reported success. ListMonitors is a separate call from both CreateMonitor attempts
    # and from the GetMonitor above, so it catches a target that silently created a second monitor
    # under the same name while only echoing ConflictException to one of the two callers.
    all_monitors = list(_paginate_monitors(nfm))
    matching = [m for m in all_monitors if m["monitorName"] == monitor_name]
    assert len(matching) == 1, (
        f"expected exactly one monitor named {monitor_name!r} via ListMonitors, got {matching}"
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


def _paginate_monitors(nfm):
    paginator = nfm.get_paginator("list_monitors")
    for page in paginator.paginate():
        yield from page.get("monitors", [])


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


def _wait_scope_succeeded(nfm, scope_id: str, timeout_s: float = 900.0) -> None:
    # A first scope activation in an account can take longer than 600 s to reach a terminal
    # status.
    final = _poll_until(
        lambda: nfm.get_scope(scopeId=scope_id)["status"],
        lambda s: s in ("SUCCEEDED", "FAILED"),
        timeout_s=timeout_s,
        interval_s=5.0,
    )
    assert final == "SUCCEEDED", f"expected scope {scope_id} to settle SUCCEEDED, got {final!r}"


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
