"""session-persistence-across-statements."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "session-persistence-across-statements"
GROUP = "state-machine"
SERVICES = ["redshift-data"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TEMP TABLE created in a session kept alive with SessionKeepAliveSeconds is visible to a later
    ExecuteStatement reusing its SessionId, the session is listed, and a call outside it FAILS."""
    _require_live_backend(ctx)
    wg = _provision_workgroup(ctx)
    rd = ctx.client("redshift-data")
    table = ctx.unique_name("sess_tmp_").replace("-", "_")

    first = rd.execute_statement(
        WorkgroupName=wg["workgroup"],
        Database=wg["database"],
        Sql=f"CREATE TEMP TABLE {table} (id INT); INSERT INTO {table} VALUES (42);",
        SessionKeepAliveSeconds=90,
    )
    session_id = first["SessionId"]
    first_final = _poll_until(
        lambda: rd.describe_statement(Id=first["Id"]),
        lambda d: d["Status"] in ("FINISHED", "FAILED", "ABORTED"),
        timeout_s=60,
        interval_s=1.0,
    )
    assert first_final["Status"] == "FINISHED", first_final.get("Error")

    # Neither WorkgroupName nor Database may be provided alongside SessionId
    # -- the session already carries its connection identity from when it
    # was opened ("There should be only one of the following: ClusterIdentifier,
    # WorkgroupName, SessionId" is the real AWS ValidationException text).
    second = rd.execute_statement(
        Sql=f"SELECT id FROM {table}",
        SessionId=session_id,
    )
    second_final = _poll_until(
        lambda: rd.describe_statement(Id=second["Id"]),
        lambda d: d["Status"] in ("FINISHED", "FAILED", "ABORTED"),
        timeout_s=60,
        interval_s=1.0,
    )
    assert second_final["Status"] == "FINISHED", second_final.get("Error")
    result = rd.get_statement_result(Id=second["Id"])
    got = result["Records"][0][0]["longValue"]
    assert got == 42, f"expected temp-table row 42 visible to the reused session, got {got!r}"

    # ListSessions rejects SessionId alongside any other filter (WorkgroupName, Status,
    # ClusterIdentifier, Database included) with "SessionId cannot be specified with other
    # filter parameters" -- SessionId alone is already the specific filter.
    sessions = rd.list_sessions(SessionId=session_id)["Sessions"]
    assert len(sessions) == 1, sessions
    assert sessions[0]["SessionId"] == session_id, (
        f"expected ListSessions to return SessionId {session_id!r}, got {sessions[0]!r}"
    )
    assert sessions[0]["Status"] in ("AVAILABLE", "BUSY"), sessions[0]

    # supporting evidence: a brand-new (non-reused) session does NOT see the
    # temp table -- state is scoped to the session, not global.
    fresh = rd.execute_statement(
        WorkgroupName=wg["workgroup"], Database=wg["database"], Sql=f"SELECT id FROM {table}"
    )
    fresh_final = _poll_until(
        lambda: rd.describe_statement(Id=fresh["Id"]),
        lambda d: d["Status"] in ("FINISHED", "FAILED", "ABORTED"),
        timeout_s=60,
        interval_s=1.0,
    )
    assert fresh_final["Status"] == "FAILED", fresh_final


def _require_live_backend(ctx) -> None:
    # The Data API's data plane is the AWS API itself (ExecuteStatement, DescribeStatement, ...),
    # so a live workgroup is all it needs; no native SQL client is involved.
    return


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

    rss.create_namespace(
        namespaceName=ns, dbName="dev", tags=[{"key": "sim2real-check", "value": CHECK}]
    )

    def _cleanup_ns():
        try:
            rss.delete_namespace(namespaceName=ns)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_ns)
    _poll_until(lambda: _namespace_ready(rss, ns), lambda ok: ok, timeout_s=180, interval_s=5)

    rss.create_workgroup(
        workgroupName=wg, namespaceName=ns, tags=[{"key": "sim2real-check", "value": CHECK}], subnetIds=ctx.network().subnet_ids
    )

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
