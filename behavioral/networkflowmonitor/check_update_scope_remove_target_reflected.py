"""update-scope-remove-target-reflected."""
from __future__ import annotations

import re

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-scope-remove-target-reflected"
GROUP = "state"
SERVICES = ["networkflowmonitor"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:networkflowmonitor-scope")
def run(ctx) -> None:
    """UpdateScope resourcesToDelete removing a scope's only target fails with ValidationException and
    the exact message (a scope keeps at least one target); its target and SUCCEEDED status stay."""
    nfm = ctx.client("networkflowmonitor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    target_a = {"targetIdentifier": {"targetId": {"accountId": account_id}, "targetType": "ACCOUNT"}, "region": ctx.region}
    scope_id = _acquire_scope(ctx, nfm, target_a)["scopeId"]

    initial = nfm.get_scope(scopeId=scope_id)
    assert initial["status"] == "SUCCEEDED", f"expected SUCCEEDED after scope acquisition, got {initial['status']!r}"
    assert initial["targets"] == [target_a], f"expected sole target {target_a!r}, got {initial['targets']!r}"

    code, message = _error_code(lambda: nfm.update_scope(scopeId=scope_id, resourcesToDelete=[target_a]))
    assert code == "ValidationException", (
        f"expected ValidationException removing the scope's only target, got {code!r}"
    )
    expected = f"invalid input -> (owner [{account_id}] cannot be removed from scope.)"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the scope's sole target and SUCCEEDED status are unchanged after the rejected call.
    unaffected = nfm.get_scope(scopeId=scope_id)
    assert unaffected["targets"] == [target_a], f"expected target unchanged at {target_a!r}, got {unaffected['targets']!r}"
    assert unaffected["status"] == "SUCCEEDED", f"expected status unchanged at SUCCEEDED, got {unaffected['status']!r}"


def _acquire_scope(ctx, nfm, target: dict, timeout_s: float = 600.0) -> dict:
    """Acquire the account's singleton NetworkFlowMonitor scope, reactivating it via UpdateScope if it
    is deactivated (NetworkFlowMonitor allows only one scope per
    account/Region and DeleteScope does not free that slot)."""
    try:
        resp = nfm.create_scope(targets=[target])
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


def _wait_scope_succeeded(nfm, scope_id: str, timeout_s: float = 600.0) -> None:
    final = _poll_until(
        lambda: nfm.get_scope(scopeId=scope_id)["status"],
        lambda s: s in ("SUCCEEDED", "FAILED"),
        timeout_s=timeout_s,
        interval_s=5.0,
    )
    assert final == "SUCCEEDED", f"expected scope to reach SUCCEEDED, got {final!r}"


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


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, so a target that
    accepts a call real AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), _without_request_suffix(error.get("Message"))
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
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

