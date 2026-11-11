"""create-capacity-reservation-by-splitting-insufficient-capacity-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-capacity-reservation-by-splitting-insufficient-capacity-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCapacityReservationBySplitting for more instances than the source has available is refused with
    InvalidParameterValue and its exact message, leaving the source's counts unchanged, while a split of 1 succeeds.
    """
    ec2 = ctx.client("ec2")
    az = _pick_availability_zone(ec2)

    source_count = 2
    source = ec2.create_capacity_reservation(
        InstanceType="t3.micro",
        InstancePlatform="Linux/UNIX",
        AvailabilityZone=az,
        InstanceCount=source_count,
        EndDateType="unlimited",
        TagSpecifications=[
            {
                "ResourceType": "capacity-reservation",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cr-split-src-")}],
            }
        ],
    )["CapacityReservation"]
    source_id = source["CapacityReservationId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.cancel_capacity_reservation(CapacityReservationId=source_id)))

    active = _poll_until(
        lambda: ec2.describe_capacity_reservations(CapacityReservationIds=[source_id])[
            "CapacityReservations"
        ][0],
        lambda cr: cr["State"] == "active",
        timeout_s=60.0,
    )
    assert active["State"] == "active", f"source reservation never became active: {active}"
    assert active["TotalInstanceCount"] == source_count, (
        f"expected TotalInstanceCount == {source_count}, got {active['TotalInstanceCount']}"
    )
    assert active["AvailableInstanceCount"] == source_count, (
        f"expected AvailableInstanceCount == {source_count}, got {active['AvailableInstanceCount']}"
    )

    # --- Negative: requesting more than remains on the source is rejected ---
    code, message = _error_detail(
        lambda: ec2.create_capacity_reservation_by_splitting(
            SourceCapacityReservationId=source_id, InstanceCount=source_count + 1
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r} ({message})"
    assert message == (
        "There isn't enough available capacity in the source Capacity Reservation. "
        f"The current available instance count is {source_count - 1}. "
        f"You requested to split {source_count + 1}."
    ), f"unexpected error message {message!r}"

    # Effect absent: the source reservation's instance count is unchanged.
    unchanged = ec2.describe_capacity_reservations(CapacityReservationIds=[source_id])[
        "CapacityReservations"
    ][0]
    assert unchanged["TotalInstanceCount"] == source_count, (
        f"expected TotalInstanceCount unchanged at {source_count}, got {unchanged['TotalInstanceCount']}"
    )
    assert unchanged["AvailableInstanceCount"] == source_count, (
        f"expected AvailableInstanceCount unchanged at {source_count}, got {unchanged['AvailableInstanceCount']}"
    )

    # --- Positive control: splitting within the available count succeeds ---
    split = ec2.create_capacity_reservation_by_splitting(
        SourceCapacityReservationId=source_id,
        InstanceCount=1,
        TagSpecifications=[
            {
                "ResourceType": "capacity-reservation",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cr-split-dst-")}],
            }
        ],
    )
    dest_id = split["DestinationCapacityReservation"]["CapacityReservationId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.cancel_capacity_reservation(CapacityReservationId=dest_id)))
    assert split["InstanceCount"] == 1, f"expected split InstanceCount == 1, got {split['InstanceCount']}"

    after_split = ec2.describe_capacity_reservations(CapacityReservationIds=[source_id])[
        "CapacityReservations"
    ][0]
    assert after_split["TotalInstanceCount"] == source_count - 1, (
        f"source reservation count did not shrink by the split amount: {after_split}"
    )


def _pick_availability_zone(ec2) -> str:
    zones = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ]
    assert zones, "no available Availability Zones in this region"
    return zones[0]["ZoneName"]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 3.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {value!r}")


def _error_detail(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidCapacityReservationId.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
