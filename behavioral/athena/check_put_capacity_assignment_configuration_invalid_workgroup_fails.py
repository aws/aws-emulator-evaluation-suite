"""put-capacity-assignment-configuration-invalid-workgroup-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-capacity-assignment-configuration-invalid-workgroup-fails"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutCapacityAssignmentConfiguration naming a nonexistent workgroup is rejected with
    InvalidRequestException; with a real workgroup it succeeds and GetCapacityAssignmentConfiguration
    returns it."""
    athena = ctx.client("athena")
    # The real workgroup's teardown is registered BEFORE the reservation's, so (LIFO) the
    # reservation is cancelled and deleted first: DeleteWorkGroup refuses a workgroup that is
    # still assigned to a reservation.
    real_workgroup = ctx.unique_name("sim2real-wg-")
    athena.create_work_group(
        Name=real_workgroup,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: athena.delete_work_group(WorkGroup=real_workgroup))

    reservation_name = ctx.unique_name("sim2real-cr-")
    athena.create_capacity_reservation(
        Name=reservation_name,
        TargetDpus=4,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _cancel_and_delete(athena, reservation_name))

    fake_workgroup = ctx.unique_name("sim2real-no-wg-")
    code, message = _error(
        lambda: athena.put_capacity_assignment_configuration(
            CapacityReservationName=reservation_name,
            CapacityAssignments=[{"WorkGroupNames": [fake_workgroup]}],
        )
    )
    assert code == "InvalidRequestException", (
        f"PutCapacityAssignmentConfiguration with nonexistent workgroup: expected "
        f"InvalidRequestException, got {code}"
    )
    assert message == "One or more WorkGroups are not found.", (
        f"PutCapacityAssignmentConfiguration with nonexistent workgroup: unexpected message "
        f"{message!r}"
    )
    # Nothing should have been stored for this reservation as a result of the
    # rejected call: the reservation has no capacity assignment configuration
    # at all yet, so GetCapacityAssignmentConfiguration succeeds but reports
    # an empty set of assignments rather than raising an error.
    stored = athena.get_capacity_assignment_configuration(
        CapacityReservationName=reservation_name
    )["CapacityAssignmentConfiguration"]
    stored_workgroups_before = [
        wg for a in stored.get("CapacityAssignments", []) for wg in a.get("WorkGroupNames", [])
    ]
    assert fake_workgroup not in stored_workgroups_before, (
        f"rejected Put must not have stored the fake workgroup, got {stored_workgroups_before}"
    )

    # Positive control: a real workgroup name is accepted and persisted.
    athena.put_capacity_assignment_configuration(
        CapacityReservationName=reservation_name,
        CapacityAssignments=[{"WorkGroupNames": [real_workgroup]}],
    )
    stored = athena.get_capacity_assignment_configuration(
        CapacityReservationName=reservation_name
    )["CapacityAssignmentConfiguration"]
    stored_workgroups = [
        wg for a in stored["CapacityAssignments"] for wg in a.get("WorkGroupNames", [])
    ]
    assert stored_workgroups == [real_workgroup], (
        f"expected stored assignment [{real_workgroup}], got {stored_workgroups}"
    )


def _error(fn):
    """The (code, message) of the ClientError `fn` raises; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError("real AWS rejects this call, but it SUCCEEDED")


def _cancel_and_delete(athena, name):
    """Wait out PENDING (CancelCapacityReservation refuses a PENDING reservation), cancel,
    wait for CANCELLED, then delete, which releases the reservation's workgroup assignments."""
    import time

    deadline = time.monotonic() + 900
    status = None
    while time.monotonic() < deadline:
        status = athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
        if status != "PENDING":
            break
        time.sleep(10)
    else:
        raise AssertionError(f"capacity reservation {name} stayed PENDING (last={status})")
    if status not in ("CANCELLING", "CANCELLED"):
        athena.cancel_capacity_reservation(Name=name)
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        status = athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
        if status == "CANCELLED":
            break
        time.sleep(5)
    else:
        raise AssertionError(f"capacity reservation {name} did not reach CANCELLED (last={status})")
    athena.delete_capacity_reservation(Name=name)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
