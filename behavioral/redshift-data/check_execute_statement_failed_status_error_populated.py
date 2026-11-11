"""execute-statement-failed-status-error-populated."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "execute-statement-failed-status-error-populated"
GROUP = "state-machine"
SERVICES = ["redshift-data"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A statement on a table that does not exist ends FAILED with a non-empty Error and no result set,
    while a valid statement finishes."""
    _require_live_backend(ctx)
    wg = _provision_workgroup(ctx)
    rd = ctx.client("redshift-data")

    # positive control: a trivially valid statement on the SAME workgroup reaches FINISHED,
    # so a target that fails every statement (not just this one) cannot pass by accident.
    control_resp = rd.execute_statement(
        WorkgroupName=wg["workgroup"], Database=wg["database"], Sql="SELECT 1"
    )
    control_final = _poll_until(
        lambda: rd.describe_statement(Id=control_resp["Id"]),
        lambda d: d["Status"] in ("FINISHED", "FAILED", "ABORTED"),
        timeout_s=90,
        interval_s=1.5,
    )
    assert control_final["Status"] == "FINISHED", (
        f"positive control: expected FINISHED for a valid statement on the same workgroup, "
        f"got {control_final['Status']!r} (error={control_final.get('Error')!r})"
    )

    resp = rd.execute_statement(
        WorkgroupName=wg["workgroup"],
        Database=wg["database"],
        Sql="SELECT * FROM sim2real_table_that_does_not_exist_xyz",
    )
    sid = resp["Id"]
    final = _poll_until(
        lambda: rd.describe_statement(Id=sid),
        lambda d: d["Status"] in ("FINISHED", "FAILED", "ABORTED"),
        timeout_s=90,
        interval_s=1.5,
    )

    assert final["Status"] == "FAILED", (
        f"expected terminal Status=FAILED for a query against a nonexistent table, "
        f"got {final['Status']!r} (final={final!r})"
    )
    assert isinstance(final.get("Error"), str) and len(final["Error"]) > 0, (
        f"expected a non-empty database Error message on the failed statement, "
        f"got {final.get('Error')!r}"
    )
    assert final["HasResultSet"] in (False, None), (
        f"expected HasResultSet False/absent on a failed statement, got {final['HasResultSet']!r}"
    )


def _require_live_backend(ctx) -> None:
    # redshift-data's data plane IS the AWS API (ExecuteStatement/DescribeStatement/...) — this
    # is not a native-protocol side-channel, so there is nothing to require here. The workgroup
    # is always provisioned for real; the harness's heavy-service timeout/concurrency budget
    # covers Redshift Serverless's multi-minute workgroup provisioning.
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
        namespaceName=ns, dbName="dev", tags=[{"key": "sim2real-behavioral", "value": "true"}]
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
        workgroupName=wg, namespaceName=ns, tags=[{"key": "sim2real-behavioral", "value": "true"}], subnetIds=ctx.network().subnet_ids
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
