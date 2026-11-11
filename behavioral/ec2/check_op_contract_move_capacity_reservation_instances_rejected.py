"""op-contract-move-capacity-reservation-instances-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-move-capacity-reservation-instances-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """MoveCapacityReservationInstances fails with InvalidCapacityReservationId.Malformed and its exact
    message for an all-zero id, a non-id string and a well-formed unknown id alike: the operation has
    no separate existence check."""
    ec2 = ctx.client("ec2")

    err, message, _ = _client_error(
        lambda: ec2.move_capacity_reservation_instances(
            SourceCapacityReservationId="cr-00000000000000000",
            DestinationCapacityReservationId="cr-00000000000000001",
            InstanceCount=1,
        )
    )
    assert err == "InvalidCapacityReservationId.Malformed", (
        f"expected InvalidCapacityReservationId.Malformed, got {err}"
    )
    assert message == "Capacity Reservation ID 'cr-00000000000000000' is malformed", f"unexpected Malformed message: {message!r}"

    err2, message2, _ = _client_error(
        lambda: ec2.move_capacity_reservation_instances(
            SourceCapacityReservationId="not-a-reservation-id",
            DestinationCapacityReservationId="cr-00000000000000001",
            InstanceCount=1,
        )
    )
    assert err2 == "InvalidCapacityReservationId.Malformed", (
        f"expected InvalidCapacityReservationId.Malformed, got {err2}"
    )
    assert message2 == "Capacity Reservation ID 'not-a-reservation-id' is malformed", f"unexpected Malformed message: {message2!r}"

    # a well-formed but nonexistent id is ALSO Malformed here: this
    # operation has no separate existence check, unlike sibling capacity-reservation operations that
    # resolve the same id shape to NotFound.
    err3, message3, _ = _client_error(
        lambda: ec2.move_capacity_reservation_instances(
            SourceCapacityReservationId="cr-0123456789abcdef0",
            DestinationCapacityReservationId="cr-0123456789abcdef1",
            InstanceCount=1,
        )
    )
    assert err3 == "InvalidCapacityReservationId.Malformed", (
        f"expected InvalidCapacityReservationId.Malformed for a well-formed but "
        f"nonexistent reservation id, got {err3}"
    )
    assert message3 == "Capacity Reservation ID 'cr-0123456789abcdef0' is malformed", f"unexpected Malformed message: {message3!r}"


def _client_error(fn):
    """Call fn() and return (code, message, http_status) of the ClientError it raises.
    An unexpected success raises AssertionError rather than returning a falsy value."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message"), exc.response["ResponseMetadata"]["HTTPStatusCode"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
