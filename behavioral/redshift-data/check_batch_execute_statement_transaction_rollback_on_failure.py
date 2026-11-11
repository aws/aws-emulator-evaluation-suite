"""batch-execute-statement-transaction-rollback-on-failure."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "batch-execute-statement-transaction-rollback-on-failure"
GROUP = "data-plane"
SERVICES = ["redshift-data"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchExecuteStatement in one transaction whose second statement fails ends FAILED with that
    statement's error, and the first statement's insert is rolled back (the table counts 0 rows)."""
    _require_live_backend(ctx)
    wg = _provision_workgroup(ctx)
    rd = ctx.client("redshift-data")
    table = ctx.unique_name("sim2real_txn_").replace("-", "_")

    _, create_final = _execute_and_wait(rd, wg, f"CREATE TABLE {table} (id INT)")
    assert create_final["Status"] == "FINISHED", create_final.get("Error")

    resp = rd.batch_execute_statement(
        WorkgroupName=wg["workgroup"],
        Database=wg["database"],
        ExecutionMode="TRANSACTION",
        Sqls=[
            f"INSERT INTO {table} VALUES (1)",
            "INSERT INTO sim2real_table_does_not_exist_xyz VALUES (2)",
        ],
    )
    parent_id = resp["Id"]
    final = _poll_until(
        lambda: rd.describe_statement(Id=parent_id),
        lambda d: d["Status"] in ("FINISHED", "FAILED", "ABORTED"),
        timeout_s=120,
        interval_s=1.5,
    )
    assert final["Status"] == "FAILED", (
        f"expected the batch to fail once its second sub-statement errors, got {final['Status']}"
    )
    sub = final.get("SubStatements", [])
    assert len(sub) == 2, f"expected 2 sub-statements, got {sub!r}"
    assert sub[1]["Status"] == "FAILED" and "sim2real_table_does_not_exist_xyz" in (sub[1].get("Error") or ""), (
        f"expected the second sub-statement to fail on the missing table, got {sub[1]!r}"
    )

    count_id, count_final = _execute_and_wait(rd, wg, f"SELECT COUNT(*) FROM {table}")
    assert count_final["Status"] == "FINISHED", (
        f"post-rollback COUNT query itself did not finish: {count_final}"
    )
    count_result = rd.get_statement_result(Id=count_id)
    assert count_result["Records"][0][0]["longValue"] == 0, (
        "first INSERT of the failed transaction was not rolled back"
    )


def _require_live_backend(ctx) -> None:
    # redshift-data's data plane IS the AWS API (ExecuteStatement/DescribeStatement/...) — this
    # is not a native-protocol side-channel, so there is nothing to route around: always provision
    # for real. The harness's heavy-service timeout/concurrency budget covers Redshift
    # Serverless's multi-minute workgroup provisioning.
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
