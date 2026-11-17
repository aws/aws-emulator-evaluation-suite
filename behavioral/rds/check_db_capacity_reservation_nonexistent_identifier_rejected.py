"""db-capacity-reservation-nonexistent-identifier-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "db-capacity-reservation-nonexistent-identifier-rejected"
GROUP = "capacity_reservations"
SERVICES = ["rds"]

_ERR_NOT_FOUND = "DBCapacityReservationNotFound"


def _rejection(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeDBCapacityReservations, ModifyDBCapacityReservation and CancelDBCapacityReservation
    each reject a well-formed identifier that names no reservation with DBCapacityReservationNotFound,
    while an unfiltered describe on the same API still succeeds."""
    rds = ctx.client("rds")

    control = rds.describe_db_capacity_reservations(MaxRecords=20)
    assert "DBCapacityReservations" in control, (
        f"positive control failed: unfiltered describe_db_capacity_reservations returned {control!r}"
    )

    ghost = ctx.unique_name("sim2real-dbcr-")

    err_describe = _rejection(
        lambda: rds.describe_db_capacity_reservations(DBCapacityReservationIdentifier=ghost)
    )
    assert err_describe.get("Code") == _ERR_NOT_FOUND, (
        f"Describe on a nonexistent identifier: expected {_ERR_NOT_FOUND}, got {err_describe}"
    )
    assert err_describe.get("Message") == (
        f"The specified DBCapacityReservation '{ghost}' does not exist."
    ), err_describe.get("Message")

    err_modify = _rejection(
        lambda: rds.modify_db_capacity_reservation(
            DBCapacityReservationIdentifier=ghost, CapacityPerAvailabilityZone=2
        )
    )
    assert err_modify.get("Code") == _ERR_NOT_FOUND, (
        f"Modify on a nonexistent identifier: expected {_ERR_NOT_FOUND}, got {err_modify}"
    )
    assert err_modify.get("Message") == (
        f"The specified DBCapacityReservation '{ghost}' does not exist."
    ), err_modify.get("Message")

    err_cancel = _rejection(
        lambda: rds.cancel_db_capacity_reservation(DBCapacityReservationIdentifier=ghost)
    )
    assert err_cancel.get("Code") == _ERR_NOT_FOUND, (
        f"Cancel on a nonexistent identifier: expected {_ERR_NOT_FOUND}, got {err_cancel}"
    )
    assert err_cancel.get("Message") == (
        f"The specified DBCapacityReservation '{ghost}' does not exist."
    ), err_cancel.get("Message")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
