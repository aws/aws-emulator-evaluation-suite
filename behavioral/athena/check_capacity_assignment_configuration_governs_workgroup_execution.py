"""capacity-assignment-configuration-governs-workgroup-execution."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capacity-assignment-configuration-governs-workgroup-execution"
GROUP = "server-side"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A workgroup bound by PutCapacityAssignmentConfiguration is reflected by the Get call, a
    query in it succeeds with the reservation still ACTIVE at unchanged TargetDpus, and clearing
    the assignment unbinds the workgroup."""
    athena = ctx.client("athena")
    bucket = _create_bucket(ctx)
    wg_name = ctx.unique_name("sim2real-athena-wg-")
    cr_name = ctx.unique_name("sim2real-athena-cr-")

    athena.create_work_group(
        Name=wg_name,
        Configuration={"ResultConfiguration": {"OutputLocation": f"s3://{bucket}/output/"}},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=wg_name, RecursiveDeleteOption=True))

    athena.create_capacity_reservation(
        Name=cr_name, TargetDpus=24, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _cancel_and_delete_reservation(ctx, cr_name))
    _poll_until(
        lambda: athena.get_capacity_reservation(Name=cr_name)["CapacityReservation"]["Status"],
        lambda s: s == "ACTIVE",
        timeout_s=900,
        interval_s=15,
    )

    athena.put_capacity_assignment_configuration(
        CapacityReservationName=cr_name,
        CapacityAssignments=[{"WorkGroupNames": [wg_name]}],
    )

    assignment_cfg = athena.get_capacity_assignment_configuration(CapacityReservationName=cr_name)[
        "CapacityAssignmentConfiguration"
    ]
    assigned_workgroups = {
        wg for a in assignment_cfg["CapacityAssignments"] for wg in a["WorkGroupNames"]
    }
    assert wg_name in assigned_workgroups, (
        f"workgroup {wg_name!r} not reflected in capacity assignment configuration: {assignment_cfg!r}"
    )

    exec_id = athena.start_query_execution(QueryString="SELECT 1", WorkGroup=wg_name)["QueryExecutionId"]
    state = _poll_until(
        lambda: athena.get_query_execution(QueryExecutionId=exec_id)["QueryExecution"]["Status"]["State"],
        lambda s: s in ("SUCCEEDED", "FAILED", "CANCELLED"),
        timeout_s=120,
        interval_s=3,
    )
    assert state == "SUCCEEDED", f"query against reserved-capacity workgroup did not succeed: {state}"

    reservation = athena.get_capacity_reservation(Name=cr_name)["CapacityReservation"]
    assert reservation["Status"] == "ACTIVE", f"reservation left in unexpected status: {reservation['Status']}"
    assert reservation["TargetDpus"] == 24, "reservation TargetDpus drifted after query execution"

    athena.put_capacity_assignment_configuration(CapacityReservationName=cr_name, CapacityAssignments=[])
    cleared_cfg = athena.get_capacity_assignment_configuration(CapacityReservationName=cr_name)[
        "CapacityAssignmentConfiguration"
    ]
    cleared_workgroups = {
        wg for a in cleared_cfg.get("CapacityAssignments", []) for wg in a.get("WorkGroupNames", [])
    }
    assert wg_name not in cleared_workgroups, (
        f"workgroup {wg_name!r} still bound after clearing capacity assignment configuration: {cleared_cfg!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-athena-out-").replace("_", "-").lower()
    if ctx.region == "us-east-1":  # S3 CreateBucket rejects LocationConstraint for this one region
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=name):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=name, Key=obj["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _cancel_and_delete_reservation(ctx, name) -> None:
    athena = ctx.client("athena")
    # A PENDING reservation refuses Cancel until it turns ACTIVE: retry it to a deadline.
    _poll_until(lambda: _try_cancel(athena, name), bool, timeout_s=300, interval_s=2)
    _poll_until(
        lambda: athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"],
        lambda s: s == "CANCELLED",
        timeout_s=300,
        interval_s=2,
    )
    try:
        athena.delete_capacity_reservation(Name=name)
    except ClientError as exc:
        if "not found" not in exc.response["Error"].get("Message", ""):
            raise


def _try_cancel(athena, name: str) -> bool:
    """Cancel the reservation; False while it is still PENDING and refuses the cancel."""
    try:
        athena.cancel_capacity_reservation(Name=name)
    except ClientError as exc:
        if "PENDING" in exc.response["Error"].get("Message", ""):
            return False
        raise
    return True


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
