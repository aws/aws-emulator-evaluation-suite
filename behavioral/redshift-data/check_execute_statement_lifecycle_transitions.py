"""execute-statement-lifecycle-transitions."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "execute-statement-lifecycle-transitions"
GROUP = "state-machine"
SERVICES = ["redshift-data"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement's DescribeStatement lifecycle moves monotonically
    SUBMITTED -> PICKED -> STARTED -> FINISHED and the terminal record carries
    accurate metadata (HasResultSet, QueryString, UpdatedAt >= CreatedAt)."""
    _require_live_backend(ctx)
    wg = _provision_workgroup(ctx)
    rd = ctx.client("redshift-data")

    resp = rd.execute_statement(WorkgroupName=wg["workgroup"], Database=wg["database"], Sql="SELECT 1")
    sid = resp["Id"]

    seen: list[str] = []

    def probe():
        d = rd.describe_statement(Id=sid)
        if not seen or seen[-1] != d["Status"]:
            seen.append(d["Status"])
        return d

    final = _poll_until(
        probe, lambda d: d["Status"] in ("FINISHED", "FAILED", "ABORTED"), timeout_s=120, interval_s=1.5
    )

    assert final["Status"] == "FINISHED", f"unexpected terminal status: {final['Status']}"
    assert final["HasResultSet"] is True, f"expected HasResultSet=True for a SELECT, got {final.get('HasResultSet')!r}"
    assert final["QueryString"] == "SELECT 1", f"expected QueryString echoed back as 'SELECT 1', got {final.get('QueryString')!r}"
    assert final["UpdatedAt"] >= final["CreatedAt"], (
        f"expected UpdatedAt ({final['UpdatedAt']}) >= CreatedAt ({final['CreatedAt']})"
    )

    order = {"SUBMITTED": 0, "PICKED": 1, "STARTED": 2, "FINISHED": 3}
    ranks = [order[s] for s in seen if s in order]
    assert ranks == sorted(ranks), f"observed out-of-order transitions: {seen}"
    assert final["Id"] == sid, f"expected the independent DescribeStatement read to echo Id={sid!r}, got {final.get('Id')!r}"


def _require_live_backend(ctx) -> None:
    """Redshift Data API has no control-plane-only surface: every operation
    needs a live cluster/workgroup to actually run SQL."""
    # redshift-data's data plane IS the AWS API (ExecuteStatement/DescribeStatement/...) — this
    # is not a native-protocol side-channel. Always provision for real; the harness's
    # heavy-service timeout/concurrency budget covers Redshift Serverless's multi-minute
    # workgroup provisioning.
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
    """Create a Redshift Serverless namespace+workgroup, wait for AVAILABLE,
    register teardown, and return identifying names/database."""
    rss = ctx.client("redshift-serverless")
    ns = ctx.unique_name("sim2real-rsns-")
    wg = ctx.unique_name("sim2real-rswg-")

    rss.create_namespace(namespaceName=ns, dbName="dev", tags=[{"key": "sim2real", "value": "true"}])

    def _cleanup_ns():
        try:
            rss.delete_namespace(namespaceName=ns)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_ns)
    _poll_until(lambda: _namespace_ready(rss, ns), lambda ok: ok, timeout_s=180, interval_s=5)

    rss.create_workgroup(workgroupName=wg, namespaceName=ns, tags=[{"key": "sim2real", "value": "true"}], subnetIds=ctx.network().subnet_ids)

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
