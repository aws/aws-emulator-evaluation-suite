"""batch-execute-statement-substatements."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "batch-execute-statement-substatements"
GROUP = "data-plane"
SERVICES = ["redshift-data"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchExecuteStatement creates sub-statements with Ids of the form
    '<parent>:N', each of which actually runs against the database (not
    just accepted and discarded) -- verified by selecting the rows back."""
    _require_live_backend(ctx)
    wg = _provision_workgroup(ctx)
    rd = ctx.client("redshift-data")
    table = ctx.unique_name("sim2real_batch_").replace("-", "_")

    resp = rd.batch_execute_statement(
        WorkgroupName=wg["workgroup"],
        Database=wg["database"],
        Sqls=[
            f"CREATE TABLE {table} (id INT)",
            f"INSERT INTO {table} VALUES (1)",
            f"INSERT INTO {table} VALUES (2)",
        ],
    )
    parent_id = resp["Id"]

    final = _poll_until(
        lambda: rd.describe_statement(Id=parent_id),
        lambda d: d["Status"] in ("FINISHED", "FAILED", "ABORTED"),
        timeout_s=120,
        interval_s=1.5,
    )
    assert final["Status"] == "FINISHED", final.get("Error")

    subs = final["SubStatements"]
    assert len(subs) == 3, subs
    for n, sub in enumerate(subs, start=1):
        assert sub["Id"] == f"{parent_id}:{n}", (sub["Id"], parent_id, n)
        assert sub["Status"] == "FINISHED", sub.get("Error")

    select_id, select_final = _execute_and_wait(rd, wg, f"SELECT COUNT(*) FROM {table}")
    assert select_final["Status"] == "FINISHED"
    count_result = rd.get_statement_result(Id=select_id)
    assert count_result["Records"][0][0]["longValue"] == 2, count_result["Records"]


def _require_live_backend(ctx) -> None:
    # redshift-data's data plane IS the AWS API (ExecuteStatement/DescribeStatement/...) — this
    # is not a native-protocol side-channel, so nothing here is optional on any backend.
    # Always provision for real; the harness's heavy-service timeout/concurrency
    # budget covers Redshift Serverless's multi-minute workgroup provisioning.
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
