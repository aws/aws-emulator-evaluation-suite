"""op-contract-get-capacity-reservation-usage."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-capacity-reservation-usage"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetCapacityReservationUsage reflects a real Capacity Reservation's usage on
    success and rejects a made-up CapacityReservationId of this shape as
    Malformed (AWS's own ID-format validation runs before any existence lookup)."""
    ec2 = ctx.client("ec2")
    cr_id = _create_capacity_reservation(ctx)

    resp = _poll_until(
        lambda: ec2.get_capacity_reservation_usage(CapacityReservationId=cr_id),
        lambda r: r.get("State") not in ("pending", "assessing", "scheduled"),
        timeout_s=120.0,
    )
    assert resp["State"] == "active", f"expected the reservation to settle active, got {resp.get('State')!r}"
    assert resp["CapacityReservationId"] == cr_id
    assert resp["InstanceType"] == "t3.micro"
    assert resp["AvailableInstanceCount"] == 1
    # The EC2 query protocol omits list fields entirely when empty, so a freshly
    # created reservation with no active instance usage may not include this key -
    # but when present or defaulted, it must actually be empty: nothing has launched
    # into this reservation yet.
    usage_set = resp.get("InstanceUsageSet", [])
    assert usage_set == [], f"expected no instance usage for a freshly created reservation, got {usage_set!r}"

    # Error boundary: a made-up CapacityReservationId of this shape does not pass
    # AWS's own ID-format validation for capacity reservations - real AWS rejects
    # it as Malformed (checked before any existence lookup happens).
    bogus_id = "cr-0123456789abcdef0"
    code, message = _error(lambda: ec2.get_capacity_reservation_usage(CapacityReservationId=bogus_id))
    assert code == "InvalidCapacityReservationId.Malformed", (
        f"expected InvalidCapacityReservationId.Malformed, got {code!r}"
    )
    assert message == f"Capacity Reservation ID '{bogus_id}' is malformed", (
        f"unexpected Malformed message: {message!r}"
    )


def _code(exc: ClientError) -> str | None:
    return exc.response.get("Error", {}).get("Code")


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return _code(exc), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float = 30.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for predicate; last value: {last!r}"
    )


def _create_capacity_reservation(ctx) -> str:
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"]
    if not zones:
        raise AssertionError("no available availability zones in this region")
    az = zones[0]["ZoneName"]

    try:
        resp = ec2.create_capacity_reservation(
            InstanceType="t3.micro",
            InstancePlatform="Linux/UNIX",
            AvailabilityZone=az,
            InstanceCount=1,
            EndDateType="unlimited",
            TagSpecifications=[
                {
                    "ResourceType": "capacity-reservation",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-")}],
                }
            ],
        )
    except ClientError as exc:
        raise AssertionError(f"could not create test Capacity Reservation: {_code(exc)}")

    cr_id = resp["CapacityReservation"]["CapacityReservationId"]
    ctx.on_cleanup(lambda: ec2.cancel_capacity_reservation(CapacityReservationId=cr_id))
    return cr_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
