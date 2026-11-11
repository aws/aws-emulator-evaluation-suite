"""cancel-statement-running-then-finished-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cancel-statement-running-then-finished-rejected"
GROUP = "overly-permissive"
SERVICES = ["redshift-data"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """CancelStatement drives a genuinely running statement to ABORTED (positive
    control), but calling it again on that now-terminal statement is rejected
    with ValidationException and does not flip the status back."""
    _require_live_backend(ctx)
    wg = _provision_workgroup(ctx)
    rd = ctx.client("redshift-data")
    table = ctx.unique_name("sim2real_lock_").replace("-", "_")

    _, create_final = _execute_and_wait(rd, wg, f"CREATE TABLE {table} (id INT)")
    assert create_final["Status"] == "FINISHED", create_final.get("Error")

    # Session 1: open a transaction and take an exclusive lock, kept alive
    # across calls via SessionKeepAliveSeconds so the lock stays held.
    holder_resp = rd.execute_statement(
        WorkgroupName=wg["workgroup"],
        Database=wg["database"],
        Sql=f"BEGIN; LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE;",
        SessionKeepAliveSeconds=120,
    )
    holder_session = holder_resp["SessionId"]
    holder_final = _poll_until(
        lambda: rd.describe_statement(Id=holder_resp["Id"]),
        lambda d: d["Status"] in ("FINISHED", "FAILED", "ABORTED"),
        timeout_s=60,
        interval_s=1.0,
    )
    assert holder_final["Status"] == "FINISHED", holder_final.get("Error")

    try:
        # Session 2 (default, new session): this blocks on the lock and
        # remains STARTED/PICKED until cancelled or the holder commits.
        blocked_resp = rd.execute_statement(
            WorkgroupName=wg["workgroup"], Database=wg["database"], Sql=f"SELECT * FROM {table}"
        )
        blocked_id = blocked_resp["Id"]

        running = _poll_until(
            lambda: rd.describe_statement(Id=blocked_id),
            lambda d: d["Status"] in ("STARTED", "PICKED"),
            timeout_s=30,
            interval_s=1.0,
        )
        assert running["Status"] in ("STARTED", "PICKED"), running

        # --- positive control: cancelling a genuinely running statement works ---
        cancel_resp = rd.cancel_statement(Id=blocked_id)
        assert cancel_resp["Status"] is True, (
            f"CancelStatement on a running statement must answer Status true, got "
            f"{cancel_resp.get('Status')!r}"
        )

        aborted = _poll_until(
            lambda: rd.describe_statement(Id=blocked_id),
            lambda d: d["Status"] in ("FINISHED", "FAILED", "ABORTED"),
            timeout_s=60,
            interval_s=1.0,
        )
        assert aborted["Status"] == "ABORTED", aborted

        # --- negative: cancelling an already-terminal statement is rejected ---
        code, status_code, message = _rejection(lambda: rd.cancel_statement(Id=blocked_id))
        assert code == "ValidationException", code
        assert status_code == 400, status_code
        assert message == (
            f"Could not cancel a query that is already in ABORTED state with ID: {blocked_id}"
        ), message

        # effect absent: status is unchanged by the rejected cancel attempt
        still = rd.describe_statement(Id=blocked_id)
        assert still["Status"] == "ABORTED", still
    finally:
        try:
            rd.execute_statement(
                WorkgroupName=wg["workgroup"],
                Database=wg["database"],
                Sql="ROLLBACK;",
                SessionId=holder_session,
            )
        except Exception:
            pass


def _require_live_backend(ctx) -> None:
    # redshift-data's data plane IS the AWS API (ExecuteStatement/DescribeStatement/...) — this
    # is not a native-protocol side-channel, so there is nothing to arrange beyond a live
    # backend. Always provision for real; the harness's heavy-service timeout/concurrency
    # budget covers Redshift Serverless's multi-minute workgroup provisioning.
    return


def _rejection(fn):
    """(error code, HTTP status, message) of the ClientError fn() raises.

    Raises AssertionError when fn() SUCCEEDS: an emulator accepting input real AWS rejects is the
    strongest signal available.
    """
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        err = e.response.get("Error", {})
        return (
            err.get("Code"),
            e.response.get("ResponseMetadata", {}).get("HTTPStatusCode"),
            err.get("Message"),
        )
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

    rss.create_workgroup(workgroupName=wg, namespaceName=ns, baseCapacity=8, subnetIds=ctx.network().subnet_ids)

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
