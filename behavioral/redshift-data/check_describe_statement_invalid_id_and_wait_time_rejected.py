"""describe-statement-invalid-id-and-wait-time-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-statement-invalid-id-and-wait-time-rejected"
GROUP = "overly-permissive"
SERVICES = ["redshift-data"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeStatement with a malformed Id and with WaitTimeSeconds outside 1-30 is rejected with
    ValidationException and its exact message, and the real statement still reads FINISHED."""
    _require_live_backend(ctx)
    wg = _provision_workgroup(ctx)
    rd = ctx.client("redshift-data")

    sid, final = _execute_and_wait(rd, wg, "SELECT 1")
    assert final["Status"] == "FINISHED", final.get("Error")

    # negative 1: malformed Id (not a UUID)
    code, msg = _client_error(lambda: rd.describe_statement(Id="not-a-valid-statement-id"))
    assert code == "ValidationException", code
    assert msg == (
        "1 validation error detected: Value 'not-a-valid-statement-id' at 'id' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        "[a-z0-9]{8}(-[a-z0-9]{4}){3}-[a-z0-9]{12}(:\\d{0,2})?"
    ), msg

    # negative 2: WaitTimeSeconds out of the documented [1,30] range
    code, msg = _client_error(lambda: rd.describe_statement(Id=sid, WaitTimeSeconds=999))
    assert code == "ValidationException", code
    assert msg == (
        "1 validation error detected: Value '999' at 'waitTimeSeconds' failed to satisfy "
        "constraint: Member must have value less than or equal to 30"
    ), msg

    # effect absent: the valid statement's own status is unaffected
    still = rd.describe_statement(Id=sid)
    assert still["Status"] == "FINISHED", still

    # positive control: a plain DescribeStatement on the same Id succeeds
    control = rd.describe_statement(Id=sid)
    assert control["Id"] == sid
    assert control["Status"] == "FINISHED"


def _require_live_backend(ctx) -> None:
    # redshift-data's data plane IS the AWS API (ExecuteStatement/DescribeStatement/...) — this
    # is not a native-protocol side-channel, so there is nothing here to route around and nothing
    # to skip. Always provision for real; the harness's heavy-service timeout/concurrency budget
    # covers Redshift Serverless's multi-minute workgroup provisioning.
    return


def _client_error(fn):
    """Call fn() and return its error as (code, message). An unexpected SUCCESS raises, because
    an emulator accepting a call real AWS refuses must not read as a code mismatch."""
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
