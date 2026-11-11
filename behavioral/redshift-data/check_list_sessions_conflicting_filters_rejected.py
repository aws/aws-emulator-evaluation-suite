"""list-sessions-conflicting-filters-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-sessions-conflicting-filters-rejected"
GROUP = "overly-permissive"
SERVICES = ["redshift-data"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ListSessions with SessionId together with Status is rejected with ValidationException and its
    exact message, while SessionId alone finds the one session the check opened."""
    _require_live_backend(ctx)
    wg = _provision_workgroup(ctx)
    rd = ctx.client("redshift-data")

    opened = rd.execute_statement(
        WorkgroupName=wg["workgroup"], Database=wg["database"], Sql="SELECT 1", SessionKeepAliveSeconds=90
    )
    session_id = opened["SessionId"]
    final = _poll_until(
        lambda: rd.describe_statement(Id=opened["Id"]),
        lambda d: d["Status"] in ("FINISHED", "FAILED", "ABORTED"),
        timeout_s=60,
        interval_s=1.0,
    )
    assert final["Status"] == "FINISHED", final.get("Error")

    # negative: SessionId together with Status is a documented mutually
    # exclusive combination. WorkgroupName is deliberately omitted here --
    # it is *itself* mutually exclusive with SessionId (see the positive
    # control below), so including it would break two rules at once and no
    # longer isolate the Status conflict this assertion names.
    code, msg = _client_error(lambda: rd.list_sessions(SessionId=session_id, Status="AVAILABLE"))
    assert code == "ValidationException", code
    assert msg == "SessionId cannot be specified with other filter parameters.", msg

    # positive control: SessionId alone (no other filter -- SessionId is
    # documented as mutually exclusive with EVERY other filter, including
    # WorkgroupName) succeeds and finds the real session
    sessions = rd.list_sessions(SessionId=session_id)["Sessions"]
    assert len(sessions) == 1, sessions
    assert sessions[0]["SessionId"] == session_id


def _require_live_backend(ctx) -> None:
    # The Data API's data plane is the AWS API itself (ExecuteStatement, DescribeStatement, ...),
    # so a live workgroup is all it needs; no native SQL client is involved.
    return


def _client_error(fn):
    """Call fn() and return its error as (code, message). An unexpected SUCCESS raises, because
    an emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s, interval_s):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _namespace_ready(rss, ns) -> bool:
    try:
        status = rss.get_namespace(namespaceName=ns).get("namespace", {}).get("status")
        return status in (None, "AVAILABLE")
    except Exception:
        return False


def _workgroup_status(rss, wg):
    try:
        return rss.get_workgroup(workgroupName=wg)["workgroup"]["status"]
    except Exception:
        return None


def _provision_workgroup(ctx) -> dict:
    rss = ctx.client("redshift-serverless")
    ns = ctx.unique_name("sim2real-rsns-")
    wg = ctx.unique_name("sim2real-rswg-")

    rss.create_namespace(namespaceName=ns, dbName="dev", tags=[{"key": "sim2real", "value": CHECK}])

    def _cleanup_ns():
        try:
            rss.delete_namespace(namespaceName=ns)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_ns)
    _poll_until(lambda: _namespace_ready(rss, ns), lambda ok: ok, timeout_s=180, interval_s=5)

    rss.create_workgroup(workgroupName=wg, namespaceName=ns, tags=[{"key": "sim2real", "value": CHECK}], subnetIds=ctx.network().subnet_ids)

    def _cleanup_wg():
        try:
            rss.delete_workgroup(workgroupName=wg)
            _poll_until(lambda: _workgroup_status(rss, wg), lambda s: s is None, timeout_s=300, interval_s=10)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_wg)
    _poll_until(
        lambda: _workgroup_status(rss, wg), lambda s: s == "AVAILABLE", timeout_s=900, interval_s=15
    )
    return {"workgroup": wg, "namespace": ns, "database": "dev"}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
