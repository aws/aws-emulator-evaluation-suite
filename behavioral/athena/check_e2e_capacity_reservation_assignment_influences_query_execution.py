"""e2e-capacity-reservation-assignment-influences-query-execution."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-capacity-reservation-assignment-influences-query-execution"
GROUP = "e2e"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A capacity reservation assigned to a workgroup via capacity assignment
    configuration lets a query in that workgroup run and succeed under the
    reservation; the assignment persists exactly as configured."""
    athena = ctx.client("athena")
    bucket = _create_bucket(ctx)
    wg_name = ctx.unique_name("sim2real-behav-capwg-")
    athena.create_work_group(
        Name=wg_name,
        Configuration={"ResultConfiguration": {"OutputLocation": f"s3://{bucket}/"}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))

    reservation_name = ctx.unique_name("sim2real-behav-capres-")
    athena.create_capacity_reservation(
        Name=reservation_name, TargetDpus=4, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _cancel_and_delete_reservation(ctx, reservation_name))

    status, reservation = _wait_reservation_status(ctx, reservation_name, {"ACTIVE", "FAILED"}, timeout_s=300)
    assert status == "ACTIVE", f"capacity reservation never became ACTIVE (status={status})"
    assert reservation["AllocatedDpus"] == reservation["TargetDpus"], (
        f"reservation reached ACTIVE without allocating its requested DPUs: {reservation!r}"
    )
    assert reservation["LastAllocation"]["Status"] == "SUCCEEDED", (
        f"reservation's own last-allocation record does not say SUCCEEDED: {reservation['LastAllocation']!r}"
    )

    athena.put_capacity_assignment_configuration(
        CapacityReservationName=reservation_name,
        CapacityAssignments=[{"WorkGroupNames": [wg_name]}],
    )
    config = athena.get_capacity_assignment_configuration(CapacityReservationName=reservation_name)[
        "CapacityAssignmentConfiguration"
    ]
    assert config["CapacityAssignments"] == [{"WorkGroupNames": [wg_name]}], (
        f"capacity assignment configuration did not persist as configured: {config!r}"
    )

    qid = athena.start_query_execution(QueryString="SELECT 1", WorkGroup=wg_name)["QueryExecutionId"]
    state, execution = _wait_query_terminal(ctx, qid, timeout_s=120)
    assert state == "SUCCEEDED", f"query under capacity reservation did not succeed: {execution['Status']}"


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-behav-athena-cap-").lower().replace("_", "-")
    kwargs = {}
    # us-east-1 rejects CreateBucketConfiguration/LocationConstraint outright; every other
    # region requires it. Not a region pin on the check itself.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
            if objs:
                failed = s3.delete_objects(Bucket=name, Delete={"Objects": objs}).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _wait_reservation_status(ctx, name: str, target_statuses: set, timeout_s: float = 300.0):
    athena = ctx.client("athena")
    deadline = time.monotonic() + timeout_s
    reservation = None
    status = None
    while time.monotonic() < deadline:
        reservation = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
        status = reservation["Status"]
        if status in target_statuses:
            return status, reservation
        time.sleep(2)
    raise AssertionError(f"capacity reservation {name} still {status!r} after {timeout_s}s")


def _cancel_and_delete_reservation(ctx, name: str) -> None:
    athena = ctx.client("athena")
    deadline = time.monotonic() + 600.0
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
        # Athena refuses a cancel while the reservation is PENDING, so it waits for ACTIVE first.
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


def _wait_query_terminal(ctx, query_execution_id: str, timeout_s: float = 120.0):
    athena = ctx.client("athena")
    deadline = time.monotonic() + timeout_s
    execution = None
    while time.monotonic() < deadline:
        execution = athena.get_query_execution(QueryExecutionId=query_execution_id)["QueryExecution"]
        state = execution["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            return state, execution
        time.sleep(2)
    raise AssertionError(f"query {query_execution_id} did not reach a terminal state in {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
