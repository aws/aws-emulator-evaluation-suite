"""concurrent-inserts-no-lost-writes."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "concurrent-inserts-no-lost-writes"
GROUP = "concurrency"
SERVICES = ["redshift-data"]

_N = 8


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Concurrently submitted ExecuteStatement INSERTs all finish, and the table then holds exactly one
    row per insert, none lost or duplicated."""
    _require_live_backend(ctx)
    wg = _provision_workgroup(ctx)
    rd = ctx.client("redshift-data")
    table = ctx.unique_name("sim2real_conc_").replace("-", "_")

    _, create_final = _execute_and_wait(rd, wg, f"CREATE TABLE {table} (id INT)")
    assert create_final["Status"] == "FINISHED", create_final.get("Error")

    def _insert(i: int) -> str:
        sid, final = _execute_and_wait(rd, wg, f"INSERT INTO {table} VALUES ({i})", timeout_s=120)
        assert final["Status"] == "FINISHED", (i, final.get("Error"))
        return final["Status"]

    with ThreadPoolExecutor(max_workers=_N) as pool:
        results = list(pool.map(_insert, range(_N)))
    assert results == ["FINISHED"] * _N, results

    sid, select_final = _execute_and_wait(rd, wg, f"SELECT id FROM {table} ORDER BY id", timeout_s=60)
    assert select_final["Status"] == "FINISHED", select_final.get("Error")
    result = rd.get_statement_result(Id=sid)
    ids = sorted(r[0]["longValue"] for r in result["Records"])
    assert ids == list(range(_N)), ids


def _require_live_backend(ctx) -> None:
    # redshift-data's data plane IS the AWS API (ExecuteStatement/DescribeStatement/...) — this
    # is not a native-protocol side-channel needing a local SQL client. It always provisions for
    # real; the harness's heavy-service timeout/concurrency budget covers Redshift Serverless's
    # multi-minute workgroup provisioning.
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
