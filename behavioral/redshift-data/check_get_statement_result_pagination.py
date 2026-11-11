"""get-statement-result-pagination."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "get-statement-result-pagination"
GROUP = "data-plane"
SERVICES = ["redshift-data"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A 90,000-row result set pages across several GetStatementResult calls via NextToken, and every
    row id comes back exactly once, none lost or duplicated."""
    _require_live_backend(ctx)
    wg = _provision_workgroup(ctx)
    rd = ctx.client("redshift-data")
    table = ctx.unique_name("sim2real_page_").replace("-", "_")

    _, create_final = _execute_and_wait(rd, wg, f"CREATE TABLE {table} (id INT, payload VARCHAR(2000))")
    assert create_final["Status"] == "FINISHED", create_final.get("Error")

    # Cross-join two bounded recursive CTEs (each well under Redshift's
    # recursive-CTE depth limit) to cheaply explode to a six-figure row
    # count without deep recursion -- 300 x 300 = 90000 rows. A narrow
    # single-INT-column version of this (90000 tiny rows, no `payload`)
    # comes back as ONE GetStatementResult page -- the row count alone does
    # not force a split. `payload` pads
    # each row to ~2000 bytes (~180MB total) so the response actually
    # crosses whatever byte threshold GetStatementResult pages on.
    _, insert_final = _execute_and_wait(
        rd,
        wg,
        (
            f"INSERT INTO {table} (id, payload) "
            "WITH RECURSIVE seq(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM seq WHERE n < 300) "
            "SELECT (a.n - 1) * 300 + b.n, "
            "LEFT(REPEAT(MD5(((a.n - 1) * 300 + b.n)::VARCHAR), 63), 2000) "
            "FROM seq a CROSS JOIN seq b"
        ),
        timeout_s=180,
    )
    assert insert_final["Status"] == "FINISHED", insert_final.get("Error")

    sid, select_final = _execute_and_wait(
        rd, wg, f"SELECT id, payload FROM {table} ORDER BY id", timeout_s=180
    )
    assert select_final["Status"] == "FINISHED", select_final.get("Error")

    seen_ids: list[int] = []
    next_token = None
    pages = 0
    total_rows = None
    while True:
        kwargs = {"Id": sid}
        if next_token:
            kwargs["NextToken"] = next_token
        page = rd.get_statement_result(**kwargs)
        pages += 1
        if total_rows is None:
            total_rows = page["TotalNumRows"]
        for rec in page["Records"]:
            seen_ids.append(rec[0]["longValue"])
        next_token = page.get("NextToken")
        if not next_token:
            break

    assert total_rows == 90000, total_rows
    assert len(seen_ids) == 90000, len(seen_ids)
    assert sorted(seen_ids) == list(range(1, 90001)), "row set mismatch (lost/duplicated rows)"
    assert pages > 1, f"expected the 90000-row result set to require multiple pages, got {pages}"


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
