"""create-capacity-reservation-fleet-targeted-match-criteria-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-capacity-reservation-fleet-targeted-match-criteria-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _usable_zone(ec2, instance_type: str) -> str:
    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    }
    usable = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
        if z["ZoneName"] in offered
    )
    assert usable, f"no available zone offers {instance_type!r}; offerings were {sorted(offered)!r}"
    return usable[0]


def _delete_fleet(ec2, fleet_id: str) -> None:
    resp = ec2.cancel_capacity_reservation_fleets(CapacityReservationFleetIds=[fleet_id])
    failed = resp.get("FailedFleetCancellations", [])
    if failed and failed[0].get("CancelCapacityReservationFleetError", {}).get("Code") not in (
        "fleet-not-found",
    ):
        raise AssertionError(f"cancelling fleet {fleet_id!r} failed: {failed!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCapacityReservationFleet rejects an InstanceMatchCriteria other than 'open'."""
    ec2 = ctx.client("ec2")
    instance_type = "t3.micro"
    zone = _usable_zone(ec2, instance_type)
    spec = [
        {
            "InstanceType": instance_type,
            "InstancePlatform": "Linux/UNIX",
            "Weight": 1.0,
            "AvailabilityZone": zone,
            "Priority": 1,
        }
    ]

    code, msg = _error(
        lambda: ec2.create_capacity_reservation_fleet(
            InstanceTypeSpecifications=spec,
            TotalTargetCapacity=1,
            InstanceMatchCriteria="targeted",
            Tenancy="default",
            AllocationStrategy="prioritized",
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    expected_msg = "targeted is not a valid value for the 'instanceMatchCriteria' parameter. Valid values include: open."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    created = ec2.create_capacity_reservation_fleet(
        InstanceTypeSpecifications=spec,
        TotalTargetCapacity=1,
        InstanceMatchCriteria="open",
        Tenancy="default",
        AllocationStrategy="prioritized",
    )
    fleet_id = created["CapacityReservationFleetId"]
    ctx.on_cleanup(lambda: _delete_fleet(ec2, fleet_id))

    described = ec2.describe_capacity_reservation_fleets(CapacityReservationFleetIds=[fleet_id])
    fleets = described["CapacityReservationFleets"]
    assert len(fleets) == 1, f"expected exactly one fleet for {fleet_id!r}, got {fleets!r}"
    assert fleets[0]["InstanceMatchCriteria"] == "open", (
        f"expected the stored fleet to keep InstanceMatchCriteria 'open', got {fleets[0]!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
