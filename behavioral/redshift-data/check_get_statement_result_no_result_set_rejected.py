"""get-statement-result-no-result-set-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-statement-result-no-result-set-rejected"
GROUP = "overly-permissive"
SERVICES = ["redshift-data"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetStatementResult on a FINISHED DDL statement with no result set is rejected with
    ResourceNotFoundException and its exact message without changing the statement, while the same
    call on a FINISHED SELECT 1 returns 1."""
    _require_live_backend(ctx)
    wg = _provision_workgroup(ctx)
    rd = ctx.client("redshift-data")
    table = ctx.unique_name("sim2real_nrs_").replace("-", "_")

    ddl_id, ddl_final = _execute_and_wait(rd, wg, f"CREATE TABLE {table} (id INT)")
    assert ddl_final["Status"] == "FINISHED", f"DDL did not finish: {ddl_final}"
    assert ddl_final["HasResultSet"] is False, f"DDL unexpectedly reports a result set: {ddl_final}"

    code, msg = _client_error(lambda: rd.get_statement_result(Id=ddl_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert msg == "Query does not have result. Please check query status with DescribeStatement.", msg

    # effect absent: the DDL statement's own record is untouched by the
    # failed result-fetch attempt
    still = rd.describe_statement(Id=ddl_id)
    assert still["Status"] == "FINISHED", f"DDL status changed after failed read: {still}"
    assert still["HasResultSet"] is False, f"DDL HasResultSet changed after failed read: {still}"

    # positive control: a SELECT (which does have a result set) succeeds
    select_id, select_final = _execute_and_wait(rd, wg, "SELECT 1")
    assert select_final["Status"] == "FINISHED", f"SELECT did not finish: {select_final}"
    assert select_final["HasResultSet"] is True, f"SELECT unexpectedly reports no result set: {select_final}"
    result = rd.get_statement_result(Id=select_id)
    got = result["Records"][0][0]["longValue"]
    assert got == 1, f"expected SELECT 1 to return 1, got {got!r}"


def _require_live_backend(ctx) -> None:
    # The Data API's data plane is the AWS API itself (ExecuteStatement, DescribeStatement, ...),
    # so a live workgroup is all it needs; no native SQL client is involved.
    return


def _client_error(fn):
    """Call fn() and return its error as (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
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
