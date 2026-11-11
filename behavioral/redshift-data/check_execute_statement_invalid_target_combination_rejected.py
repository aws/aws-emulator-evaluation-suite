"""execute-statement-invalid-target-combination-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "execute-statement-invalid-target-combination-rejected"
GROUP = "overly-permissive"
SERVICES = ["redshift-data"]
_ONE_TARGET_MESSAGE = (
    "There should be only one of the following: ClusterIdentifier, WorkgroupName, Glue resource, SessionId"
)


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteStatement with no target, and with both ClusterIdentifier and WorkgroupName, is rejected
    with ValidationException and its exact message and leaves no statement, while a single target
    finishes."""
    _require_live_backend(ctx)
    wg = _provision_workgroup(ctx)
    rd = ctx.client("redshift-data")

    before_count = len(rd.list_statements(WorkgroupName=wg["workgroup"])["Statements"])

    # negative 1: no ClusterIdentifier, no WorkgroupName, no SecretArn at all
    code, msg = _client_error(lambda: rd.execute_statement(Database=wg["database"], Sql="SELECT 1"))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert msg == _ONE_TARGET_MESSAGE, msg

    # negative 2: both ClusterIdentifier and WorkgroupName supplied
    code, msg = _client_error(
        lambda: rd.execute_statement(
            ClusterIdentifier="sim2real-bogus-cluster",
            WorkgroupName=wg["workgroup"],
            Database=wg["database"],
            Sql="SELECT 1",
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    assert msg == _ONE_TARGET_MESSAGE, msg

    after_count = len(rd.list_statements(WorkgroupName=wg["workgroup"])["Statements"])
    assert after_count == before_count, "a rejected ExecuteStatement call left behind a statement record"

    # positive control: a valid single-target combination succeeds
    sid, final = _execute_and_wait(rd, wg, "SELECT 1")
    assert final["Status"] == "FINISHED", f"expected FINISHED, got {final['Status']}: {final.get('Error')}"


def _require_live_backend(ctx) -> None:
    # redshift-data's data plane IS the AWS API (ExecuteStatement/DescribeStatement/...) — this
    # is not a native-protocol side-channel, so there is nothing to require here. The workgroup
    # is always provisioned for real; the harness's heavy-service timeout/concurrency budget
    # covers Redshift Serverless's multi-minute workgroup provisioning.
    return


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


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

    rss.create_workgroup(
        workgroupName=wg, namespaceName=ns, baseCapacity=8, tags=[{"key": "sim2real", "value": CHECK}], subnetIds=ctx.network().subnet_ids
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
