"""delete-scope-removes-scope."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-scope-removes-scope"
GROUP = "state"
SERVICES = ["networkflowmonitor"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:networkflowmonitor-scope")
def run(ctx) -> None:
    """DeleteScope REMOVES an unreferenced SUCCEEDED scope: GetScope then answers
    ResourceNotFoundException, ListScopes no longer reports it, and a repeat DeleteScope is likewise
    ResourceNotFoundException; the one scope per account/Region allowed is adopted when present."""
    nfm = ctx.client("networkflowmonitor")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    target = {"targetIdentifier": {"targetId": {"accountId": account_id}, "targetType": "ACCOUNT"}, "region": ctx.region}
    scope_id = _acquire_scope(ctx, nfm, target)["scopeId"]

    # NetworkFlowMonitor rejects DeleteScope while any monitor still references the scope, and since
    # this account has only one (singleton) scope, every existing monitor references it -- clear them.
    _delete_all_monitors(nfm)

    nfm.delete_scope(scopeId=scope_id)

    final = _poll_until(
        _scope_status_or_removed(nfm, scope_id),
        lambda s: s in ("DEACTIVATED", "FAILED", "<REMOVED>"),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert final == "<REMOVED>", (
        f"expected DeleteScope to REMOVE scope {scope_id} (GetScope -> ResourceNotFoundException), "
        f"but GetScope still reports status {final!r}"
    )

    # ListScopes agrees with GetScope -- the scope is not merely unreadable by id.
    listed = {s["scopeId"] for s in nfm.list_scopes().get("scopes", [])}
    assert scope_id not in listed, f"deleted scope {scope_id} still appears in ListScopes: {sorted(listed)}"

    # A second DeleteScope is refused as not-found, not accepted as a no-op: the resource is gone,
    # not sitting in a terminal deactivated state that tolerates repeat deletes.
    redelete_code, redelete_message = _error_code(lambda: nfm.delete_scope(scopeId=scope_id))
    assert redelete_code == "ResourceNotFoundException", (
        f"expected a repeat DeleteScope to be ResourceNotFoundException, got {redelete_code!r}"
    )
    assert redelete_message == f"There's no scope with ARN: [arn:aws:networkflowmonitor:{ctx.region}:{ctx.account}:scope/{scope_id}]", (
        f"expected the exact ResourceNotFoundException message AWS returns, got {redelete_message!r}"
    )


# ===== helpers =====

def _delete_all_monitors(nfm, timeout_s: float = 120.0, interval_s: float = 10.0) -> None:
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
        deadline = time.monotonic() + timeout_s
        while True:
            try:
                nfm.delete_monitor(monitorName=name)
                break
            except ClientError as err:
                code = err.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    break
                if code == "ConflictException" and time.monotonic() < deadline:
                    # The monitor is likely still settling into ACTIVE/DELETING; retry.
                    time.sleep(interval_s)
                    continue
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

def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because a target
    ACCEPTING a call real AWS refuses is the strongest divergence signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"real AWS refuses this call, but it SUCCEEDED and returned {result!r}")


def _scope_status_or_removed(nfm, scope_id: str):
    """GetScope's status, or the sentinel ``<REMOVED>`` when GetScope 404s.

    The distinction is the whole point of this check -- "deactivated, not removed" -- so a
    post-delete 404 has to be a reportable OUTCOME rather than an exception escaping the poll.
    """
    def probe():
        try:
            return nfm.get_scope(scopeId=scope_id)["status"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                return "<REMOVED>"
            raise

    return probe


def _acquire_scope(ctx, nfm, target: dict, timeout_s: float = 1500.0) -> dict:
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


def _wait_scope_succeeded(nfm, scope_id: str, timeout_s: float = 600.0) -> None:
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

