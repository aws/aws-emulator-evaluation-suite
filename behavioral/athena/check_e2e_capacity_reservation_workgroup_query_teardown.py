"""e2e-capacity-reservation-workgroup-query-teardown."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-capacity-reservation-workgroup-query-teardown"
GROUP = "e2e"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A reservation assigned to a workgroup reaches ACTIVE with all DPUs allocated, a query in the
    workgroup succeeds, and after teardown reads and mutations of both fail as not found."""
    athena = ctx.client("athena")
    s3 = ctx.client("s3")

    bucket = ctx.unique_name("sim2real-athena-cr-")
    _create_bucket(ctx, s3, bucket)

    wg_name = ctx.unique_name("sim2real-athena-cr-wg-")
    athena.create_work_group(
        Name=wg_name,
        Configuration={"ResultConfiguration": {"OutputLocation": f"s3://{bucket}/results/"}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_workgroup(athena, wg_name))

    cr_name = ctx.unique_name("sim2real-athena-cr-")
    athena.create_capacity_reservation(Name=cr_name, TargetDpus=4, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _safe_delete_capacity_reservation(athena, cr_name))

    athena.put_capacity_assignment_configuration(
        CapacityReservationName=cr_name,
        CapacityAssignments=[{"WorkGroupNames": [wg_name]}],
    )

    def _active():
        cr = athena.get_capacity_reservation(Name=cr_name)["CapacityReservation"]
        if cr["Status"] == "ACTIVE":
            return cr
        if cr["Status"] == "FAILED":
            raise AssertionError(f"capacity reservation entered FAILED status: {cr}")
        return None

    cr = _poll_until(_active, timeout_s=900, interval_s=20)
    assert cr["AllocatedDpus"] == cr["TargetDpus"], cr
    assert cr["LastAllocation"]["Status"] == "SUCCEEDED", cr["LastAllocation"]

    qid = athena.start_query_execution(QueryString="SELECT 1", WorkGroup=wg_name)[
        "QueryExecutionId"
    ]

    def _q_terminal():
        qe = athena.get_query_execution(QueryExecutionId=qid)["QueryExecution"]
        state = qe["Status"]["State"]
        return qe if state in ("SUCCEEDED", "FAILED", "CANCELLED") else None

    qe = _poll_until(_q_terminal, timeout_s=120, interval_s=3)
    assert qe["Status"]["State"] == "SUCCEEDED", qe["Status"].get("StateChangeReason")
    assert qe["WorkGroup"] == wg_name, f"expected query bound to {wg_name!r}, got {qe['WorkGroup']!r}"

    # AWS rejects DeleteWorkGroup on an assigned workgroup ("WorkGroup is assigned to a
    # reservation"), so the reservation goes first; the workgroup then needs the recursive
    # option because it still owns a query execution.
    athena.cancel_capacity_reservation(Name=cr_name)

    def _cancelled():
        cr2 = athena.get_capacity_reservation(Name=cr_name)["CapacityReservation"]
        return cr2 if cr2["Status"] == "CANCELLED" else None

    _poll_until(_cancelled, timeout_s=180, interval_s=10)
    athena.delete_capacity_reservation(Name=cr_name)

    athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True)

    wg_read_code, wg_read_msg = _error(lambda: athena.get_work_group(WorkGroup=wg_name))
    assert wg_read_code == "InvalidRequestException", (
        f"expected GetWorkGroup on a deleted workgroup to raise InvalidRequestException, got {wg_read_code!r}"
    )
    assert wg_read_msg == "WorkGroup is not found.", wg_read_msg
    wg_mutate_code, wg_mutate_msg = _error(
        lambda: athena.start_query_execution(QueryString="SELECT 1", WorkGroup=wg_name)
    )
    assert wg_mutate_code == "InvalidRequestException", (
        f"expected StartQueryExecution against a deleted workgroup to raise InvalidRequestException, "
        f"got {wg_mutate_code!r}"
    )
    assert wg_mutate_msg == "WorkGroup is not found.", wg_mutate_msg

    expected_cr_msg = f"Reservation with name {cr_name} not found."
    cr_read_code, cr_read_msg = _error(lambda: athena.get_capacity_reservation(Name=cr_name))
    assert cr_read_code == "InvalidRequestException", (
        f"expected GetCapacityReservation on a deleted reservation to raise InvalidRequestException, "
        f"got {cr_read_code!r}"
    )
    assert cr_read_msg == expected_cr_msg, f"expected {expected_cr_msg!r}, got {cr_read_msg!r}"
    cr_mutate_code, cr_mutate_msg = _error(lambda: athena.cancel_capacity_reservation(Name=cr_name))
    assert cr_mutate_code == "InvalidRequestException", (
        f"expected CancelCapacityReservation against a deleted reservation to raise "
        f"InvalidRequestException, got {cr_mutate_code!r}"
    )
    assert cr_mutate_msg == expected_cr_msg, f"expected {expected_cr_msg!r}, got {cr_mutate_msg!r}"


def _create_bucket(ctx, s3, bucket: str) -> None:
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})


def _safe_delete_workgroup(athena, name: str) -> None:
    try:
        athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True)
    except ClientError as exc:
        if not _not_found(exc):
            raise


def _safe_delete_capacity_reservation(athena, name: str) -> None:
    deadline = time.monotonic() + 600
    cancel_sent = False
    while True:
        try:
            status = athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
        except ClientError as exc:
            if not _not_found(exc):
                raise
            return
        if status in ("CANCELLED", "FAILED"):
            break
        # Athena refuses a cancel while the reservation is PENDING or UPDATE_PENDING.
        if status == "ACTIVE" and not cancel_sent:
            try:
                athena.cancel_capacity_reservation(Name=name)
                cancel_sent = True
            except ClientError as exc:
                msg = exc.response["Error"].get("Message", "")
                if "when state is" in msg and "PENDING" in msg:
                    pass
                elif _not_found(exc) or ("when state is" in msg and "CANCEL" in msg):
                    cancel_sent = True
                else:
                    raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"capacity reservation {name} still {status!r} after 600s of teardown")
        time.sleep(2)
    try:
        athena.delete_capacity_reservation(Name=name)
    except ClientError as exc:
        if not _not_found(exc):
            raise


def _not_found(exc: ClientError) -> bool:
    """Athena reports a missing resource as ResourceNotFoundException or an InvalidRequestException saying so."""
    err = exc.response["Error"]
    msg = err.get("Message", "")
    return err.get("Code") == "ResourceNotFoundException" or (
        err.get("Code") == "InvalidRequestException" and ("not found" in msg or "does not exist" in msg)
    )


def _error(fn):
    """Call fn(); return its ClientError (code, message), or fail if the call succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        result = probe()
        if result is not None:
            return result
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
