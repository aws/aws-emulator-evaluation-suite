"""execute-statement-nonexistent-workgroup-not-found."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "execute-statement-nonexistent-workgroup-not-found"
GROUP = "rejection"
SERVICES = ["redshift-data"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement on a WorkgroupName that does not exist is rejected with ValidationException
    ("Redshift endpoint doesn't exist in this region.") and leaves no statement, while the real
    workgroup's statement finishes and is listed."""
    _require_live_backend(ctx)
    wg = _provision_workgroup(ctx)
    rd = ctx.client("redshift-data")

    bogus_workgroup = ctx.unique_name("sim2real-nonexistent-wg-")
    code, message = _error_code_and_message(
        lambda: rd.execute_statement(
            WorkgroupName=bogus_workgroup, Database=wg["database"], Sql="SELECT 1"
        )
    )
    assert code == "ValidationException", (code, message)
    assert message == "Redshift endpoint doesn't exist in this region.", message

    # effect absent: ListStatements filters by workgroup without an existence
    # check (no error) -- but under a bogus/never-used workgroup name, it
    # legitimately finds zero statements.
    listed = rd.list_statements(WorkgroupName=bogus_workgroup)["Statements"]
    assert listed == [], listed

    # positive control: the real workgroup works
    sid, final = _execute_and_wait(rd, wg, "SELECT 1")
    assert final["Status"] == "FINISHED", final.get("Error")

    # Calibration: the empty read above is only meaningful if ListStatements
    # promptly reflects reality on this same wiring. Demonstrate that now, using
    # the statement the positive control just ran, rather than assuming it.
    seen = _poll_until(
        lambda: rd.list_statements(WorkgroupName=wg["workgroup"])["Statements"],
        lambda ss: any(s["Id"] == sid for s in ss),
        timeout_s=30,
        interval_s=1.5,
    )
    assert any(s["Id"] == sid for s in seen), seen


def _require_live_backend(ctx) -> None:
    # redshift-data's data plane IS the AWS API (ExecuteStatement/DescribeStatement/...) — this
    # is not a native-protocol side-channel, so nothing here is optional on any backend.
    # Always provision for real; the harness's heavy-service timeout/concurrency
    # budget covers Redshift Serverless's multi-minute workgroup provisioning.
    return


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection but the call SUCCEEDED, returning {result!r}")


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

    rss.create_namespace(namespaceName=ns, dbName="dev")

    def _cleanup_ns():
        try:
            rss.delete_namespace(namespaceName=ns)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_ns)
    _poll_until(lambda: _namespace_ready(rss, ns), lambda ok: ok, timeout_s=180, interval_s=5)

    rss.create_workgroup(workgroupName=wg, namespaceName=ns, subnetIds=ctx.network().subnet_ids)

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
