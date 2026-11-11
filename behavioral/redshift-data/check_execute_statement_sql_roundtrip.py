"""execute-statement-sql-roundtrip."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "execute-statement-sql-roundtrip"
GROUP = "data-plane"
SERVICES = ["redshift-data"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CREATE TABLE, INSERT and SELECT through ExecuteStatement actually run on the engine, and
    GetStatementResult returns the committed row values, so a stub that accepts the SQL fails."""
    _require_live_backend(ctx)
    wg = _provision_workgroup(ctx)
    rd = ctx.client("redshift-data")
    table = ctx.unique_name("sim2real_tbl_").replace("-", "_")

    _, create_final = _execute_and_wait(rd, wg, f"CREATE TABLE {table} (id INT, name VARCHAR(50))")
    assert create_final["Status"] == "FINISHED", create_final.get("Error")

    _, insert_final = _execute_and_wait(rd, wg, f"INSERT INTO {table} VALUES (1,'alice'), (2,'bob')")
    assert insert_final["Status"] == "FINISHED", insert_final.get("Error")

    sid, select_final = _execute_and_wait(rd, wg, f"SELECT id, name FROM {table} ORDER BY id")
    assert select_final["Status"] == "FINISHED", select_final.get("Error")
    assert select_final["HasResultSet"] is True, select_final

    result = rd.get_statement_result(Id=sid)
    cols = [c["name"] for c in result["ColumnMetadata"]]
    assert cols == ["id", "name"], cols
    values = [(r[0].get("longValue"), r[1].get("stringValue")) for r in result["Records"]]
    assert values == [(1, "alice"), (2, "bob")], f"expected [(1, 'alice'), (2, 'bob')], got {values}"
    assert result["TotalNumRows"] == 2, result["TotalNumRows"]


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
        namespaceName=ns, dbName="dev", tags=[{"key": "sim2real", "value": "true"}]
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
        workgroupName=wg, namespaceName=ns, tags=[{"key": "sim2real", "value": "true"}], subnetIds=ctx.network().subnet_ids
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


def _execute_and_wait(rd, wg, sql, timeout_s=90, **kwargs):
    resp = rd.execute_statement(WorkgroupName=wg["workgroup"], Database=wg["database"], Sql=sql, **kwargs)
    sid = resp["Id"]
    final = _poll_until(
        lambda: rd.describe_statement(Id=sid),
        lambda d: d["Status"] in ("FINISHED", "FAILED", "ABORTED"),
        timeout_s=timeout_s,
        interval_s=1.5,
    )
    return sid, final


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
