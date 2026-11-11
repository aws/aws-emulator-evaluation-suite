"""list-monitors-invalid-next-token-rejected."""
from __future__ import annotations

import re

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-monitors-invalid-next-token-rejected"
GROUP = "overly-permissive"
SERVICES = ["networkflowmonitor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:networkflowmonitor-scope")
def run(ctx) -> None:
    """ListMonitors rejects a garbage nextToken with ValidationException "NextToken provided isn't
    valid.", while a real nextToken from a maxResults=1 page over two created monitors is accepted."""
    nfm = ctx.client("networkflowmonitor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    code, message = _error_code(lambda: nfm.list_monitors(nextToken="sim2real-not-a-real-pagination-token"))
    assert code == "ValidationException", f"expected ValidationException for a garbage nextToken, got {code!r}"
    assert message == "NextToken provided isn't valid.", f"expected the invalid-token message, got {message!r}"

    scope = _create_scope(ctx, nfm, [_target(account_id, ctx.region)])
    _wait_scope_succeeded(nfm, scope["scopeId"])

    for i in range(2):
        name = ctx.unique_name(f"sim2real-nfm-pg{i}-")
        nfm.create_monitor(
            monitorName=name,
            localResources=[{"type": "AWS::Region", "identifier": ctx.region}],
            scopeArn=scope["scopeArn"],
            tags={"sim2real-owner": "behavioral-suite"},
        )
        ctx.on_cleanup(lambda name=name: _safe_delete_monitor(nfm, name))

    first_page = nfm.list_monitors(maxResults=1)
    assert len(first_page["monitors"]) == 1, f"expected exactly 1 monitor per page, got {len(first_page['monitors'])}"
    valid_token = first_page.get("nextToken")
    assert valid_token, "expected a nextToken with more than 1 monitor in the account and maxResults=1"

    second_page = nfm.list_monitors(nextToken=valid_token)
    assert isinstance(second_page["monitors"], list), "a genuinely valid nextToken must be accepted, not rejected"


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
    assert final == "SUCCEEDED", f"expected scope to reach SUCCEEDED, got {final!r}"


def _error_code(fn):
    """Call fn(); return its ClientError (code, message without the per-request suffix)."""
    try:
        fn()
    except ClientError as err:
        error = err.response["Error"]
        return error["Code"], _without_request_suffix(error.get("Message"))
    raise AssertionError("expected the call to raise a ClientError, it succeeded instead")


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
