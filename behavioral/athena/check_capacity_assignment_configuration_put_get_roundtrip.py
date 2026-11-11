"""capacity-assignment-configuration-put-get-roundtrip."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "capacity-assignment-configuration-put-get-roundtrip"
GROUP = "state-machine"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutCapacityAssignmentConfiguration persists a workgroup-to-capacity mapping that
    GetCapacityAssignmentConfiguration returns unchanged, and reflects updates on a
    subsequent put/get round trip."""
    athena = ctx.client("athena")
    cr_name = ctx.unique_name("sim2real-cr-cac-")
    wg1 = ctx.unique_name("sim2real-wg-cac-a-")
    wg2 = ctx.unique_name("sim2real-wg-cac-b-")

    tag = [{"Key": "sim2real", "Value": CHECK}]
    athena.create_work_group(Name=wg1, Tags=tag)
    ctx.on_cleanup(lambda: _safe_delete_wg(athena, wg1))
    athena.create_work_group(Name=wg2, Tags=tag)
    ctx.on_cleanup(lambda: _safe_delete_wg(athena, wg2))

    athena.create_capacity_reservation(Name=cr_name, TargetDpus=4, Tags=tag)
    ctx.on_cleanup(lambda: _safe_teardown_cr(athena, cr_name))

    athena.put_capacity_assignment_configuration(
        CapacityReservationName=cr_name,
        CapacityAssignments=[{"WorkGroupNames": [wg1]}],
    )
    got1 = athena.get_capacity_assignment_configuration(CapacityReservationName=cr_name)[
        "CapacityAssignmentConfiguration"
    ]
    assert got1["CapacityReservationName"] == cr_name, (
        f"expected CapacityReservationName {cr_name!r}, got {got1['CapacityReservationName']!r}"
    )
    assert got1["CapacityAssignments"] == [{"WorkGroupNames": [wg1]}], (
        f"expected assignments [{{'WorkGroupNames': [{wg1!r}]}}], got {got1['CapacityAssignments']!r}"
    )

    # Re-read without mutating: value must be stable across reads.
    got1_again = athena.get_capacity_assignment_configuration(CapacityReservationName=cr_name)[
        "CapacityAssignmentConfiguration"
    ]
    assert got1_again["CapacityAssignments"] == [{"WorkGroupNames": [wg1]}], (
        f"expected unchanged assignments [{{'WorkGroupNames': [{wg1!r}]}}] on re-read, "
        f"got {got1_again['CapacityAssignments']!r}"
    )

    # Overwrite the mapping and confirm the round trip reflects the new value exactly.
    athena.put_capacity_assignment_configuration(
        CapacityReservationName=cr_name,
        CapacityAssignments=[{"WorkGroupNames": [wg1, wg2]}],
    )
    got2 = athena.get_capacity_assignment_configuration(CapacityReservationName=cr_name)[
        "CapacityAssignmentConfiguration"
    ]
    assert got2["CapacityAssignments"] == [{"WorkGroupNames": [wg1, wg2]}], (
        f"expected assignments [{{'WorkGroupNames': [{wg1!r}, {wg2!r}]}}] after overwrite, "
        f"got {got2['CapacityAssignments']!r}"
    )
    assert got2["CapacityAssignments"] != got1["CapacityAssignments"], (
        "expected the overwritten assignment to differ from the original "
        f"assignment, both are {got2['CapacityAssignments']!r}"
    )


def _safe_delete_wg(athena: Any, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True)
    except ClientError as exc:
        if "not found" not in exc.response["Error"].get("Message", ""):
            raise


def _safe_teardown_cr(athena: Any, name: str) -> None:
    import time

    from botocore.exceptions import ClientError

    # Cancel once the reservation is ACTIVE (PENDING refuses Cancel), delete it once CANCELLED;
    # only an unknown name ("... not found.") counts as already gone.
    cancelled = False
    deadline = time.monotonic() + 180.0
    while time.monotonic() < deadline:
        try:
            status = athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
            if status in ("CANCELLED", "FAILED"):
                athena.delete_capacity_reservation(Name=name)
                return
            if status == "ACTIVE" and not cancelled:
                athena.cancel_capacity_reservation(Name=name)
                cancelled = True
        except ClientError as exc:
            if "not found" in exc.response["Error"].get("Message", ""):
                return
            raise
        time.sleep(2.0)
    raise TimeoutError(f"capacity reservation {name} not deleted within 180s (last status {status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
