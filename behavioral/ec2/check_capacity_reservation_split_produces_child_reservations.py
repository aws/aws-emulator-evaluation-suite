"""capacity-reservation-split-produces-child-reservations."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags


CHECK = "capacity-reservation-split-produces-child-reservations"
GROUP = "state-machine"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Splitting 3 of a 4-instance Capacity Reservation leaves the source active with 1 and a new active
    reservation with 3 (total 4), and splitting off the source's last instance is refused with
    InvalidParameterValue.
    """
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-crsplit-")
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    source_id = ec2.create_capacity_reservation(
        InstanceType="t3.micro",
        InstancePlatform="Linux/UNIX",
        AvailabilityZone=az,
        InstanceCount=4,
        TagSpecifications=_tag_spec("capacity-reservation", name),
    )["CapacityReservation"]["CapacityReservationId"]

    ctx.on_cleanup(lambda: _cancel_tolerating_gone(ec2, source_id))

    def _source_state():
        return ec2.describe_capacity_reservations(CapacityReservationIds=[source_id])[
            "CapacityReservations"
        ][0]["State"]

    _poll_until(_source_state, lambda s: s == "active", timeout_s=60, interval_s=3)

    # Split off 3 of the 4 instances -- the maximum allowed (source size - 1).
    split = ec2.create_capacity_reservation_by_splitting(
        SourceCapacityReservationId=source_id,
        InstanceCount=3,
        TagSpecifications=_tag_spec("capacity-reservation", name + "-child"),
    )
    dest_id = split["DestinationCapacityReservation"]["CapacityReservationId"]

    ctx.on_cleanup(lambda: _cancel_tolerating_gone(ec2, dest_id))

    assert split["InstanceCount"] == 3, f"expected split response InstanceCount 3, got {split['InstanceCount']!r}"
    assert split["DestinationCapacityReservation"]["TotalInstanceCount"] == 3, (
        f"expected destination TotalInstanceCount 3, got {split['DestinationCapacityReservation']['TotalInstanceCount']!r}"
    )
    assert split["SourceCapacityReservation"]["TotalInstanceCount"] == 1, (
        f"expected source TotalInstanceCount 1, got {split['SourceCapacityReservation']['TotalInstanceCount']!r}"
    )

    def _both_states():
        crs = ec2.describe_capacity_reservations(CapacityReservationIds=[source_id, dest_id])[
            "CapacityReservations"
        ]
        by_id = {c["CapacityReservationId"]: c for c in crs}
        return by_id[source_id]["State"], by_id[dest_id]["State"]

    source_state, dest_state = _poll_until(
        _both_states, lambda st: st[0] == "active" and st[1] == "active", timeout_s=90, interval_s=3
    )
    assert source_state == "active", f"expected source state active, got {source_state!r}"
    assert dest_state == "active", f"expected destination state active, got {dest_state!r}"

    final = ec2.describe_capacity_reservations(CapacityReservationIds=[source_id, dest_id])[
        "CapacityReservations"
    ]
    by_id = {c["CapacityReservationId"]: c for c in final}
    # Combined total capacity is preserved across the split.
    assert by_id[source_id]["TotalInstanceCount"] == 1, (
        f"expected source TotalInstanceCount 1, got {by_id[source_id]['TotalInstanceCount']!r}"
    )
    assert by_id[dest_id]["TotalInstanceCount"] == 3, (
        f"expected destination TotalInstanceCount 3, got {by_id[dest_id]['TotalInstanceCount']!r}"
    )
    assert by_id[source_id]["TotalInstanceCount"] + by_id[dest_id]["TotalInstanceCount"] == 4, (
        "combined total instance count must equal the pre-split source count of 4, got "
        f"{by_id[source_id]['TotalInstanceCount'] + by_id[dest_id]['TotalInstanceCount']!r}"
    )

    # Attempting to split off the source's LAST remaining instance is
    # rejected -- at least one instance must always remain in the source.
    code, message = _error_detail(
        lambda: ec2.create_capacity_reservation_by_splitting(
            SourceCapacityReservationId=source_id,
            InstanceCount=1,
            TagSpecifications=_tag_spec("capacity-reservation", name + "-overflow"),
        )
    )
    assert code == "InvalidParameterValue", (
        f"expected InvalidParameterValue splitting off the source's last instance, got {code!r} ({message})"
    )
    assert message == (
        "There isn't enough available capacity in the source Capacity Reservation. "
        "The current available instance count is 0. You requested to split 1."
    ), f"unexpected error message {message!r}"

    # Effect absent: the rejected split left the source's count untouched.
    unchanged = ec2.describe_capacity_reservations(CapacityReservationIds=[source_id])[
        "CapacityReservations"
    ][0]
    assert unchanged["TotalInstanceCount"] == 1, (
        f"expected source TotalInstanceCount to remain 1 after the rejected split, got {unchanged['TotalInstanceCount']!r}"
    )


def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _error_detail(fn: Callable[[], Any]):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _cancel_tolerating_gone(ec2, cr_id: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ec2.cancel_capacity_reservation(CapacityReservationId=cr_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("IncorrectState", "InvalidCapacityReservationId.NotFound"):
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
