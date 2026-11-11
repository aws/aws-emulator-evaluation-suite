"""groups-for-capacity-reservation-reflects-fleet-association."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "groups-for-capacity-reservation-reflects-fleet-association"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetGroupsForCapacityReservation returns exactly the resource group the reservation was added to."""
    ec2 = ctx.client("ec2")
    rg = ctx.client("resource-groups")

    az = _pick_availability_zone(ec2)
    resp = ec2.create_capacity_reservation(
        InstanceType="t3.micro",
        InstancePlatform="Linux/UNIX",
        AvailabilityZone=az,
        InstanceCount=1,
        EndDateType="unlimited",
        TagSpecifications=[
            {
                "ResourceType": "capacity-reservation",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-cr-group-")}],
            }
        ],
    )
    cr = resp["CapacityReservation"]
    cr_id = cr["CapacityReservationId"]
    ctx.on_cleanup(lambda: ec2.cancel_capacity_reservation(CapacityReservationId=cr_id))

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    cr_arn = f"arn:aws:ec2:{ctx.region}:{account_id}:capacity-reservation/{cr_id}"

    group_name = ctx.unique_name("sim2real-cr-group-")
    rg.create_group(
        Name=group_name,
        Configuration=[
            {"Type": "AWS::EC2::CapacityReservationPool", "Parameters": []},
            {
                "Type": "AWS::ResourceGroups::Generic",
                "Parameters": [
                    {"Name": "allowed-resource-types", "Values": ["AWS::EC2::CapacityReservation"]}
                ],
            },
        ],
    )
    ctx.on_cleanup(lambda: rg.delete_group(Group=group_name))

    # Only 'active' Capacity Reservations can be added to a resource group.
    _poll_until(
        lambda: ec2.describe_capacity_reservations(CapacityReservationIds=[cr_id])[
            "CapacityReservations"
        ][0]["State"],
        lambda state: state == "active",
        timeout_s=60.0,
        interval_s=3.0,
        description=f"capacity reservation {cr_id} to become active",
    )

    rg.group_resources(Group=group_name, ResourceArns=[cr_arn])
    ctx.on_cleanup(lambda: rg.ungroup_resources(Group=group_name, ResourceArns=[cr_arn]))

    groups = _poll_until(
        lambda: ec2.get_groups_for_capacity_reservation(CapacityReservationId=cr_id)[
            "CapacityReservationGroups"
        ],
        lambda gs: len(gs) >= 1,
        timeout_s=60.0,
        interval_s=3.0,
        description=f"GetGroupsForCapacityReservation to reflect group {group_name!r} for {cr_id}",
    )
    group_arns = {g["GroupArn"] for g in groups}
    matching = [arn for arn in group_arns if arn.endswith(f"/{group_name}") or arn.endswith(f":{group_name}")]
    assert matching, (
        f"GetGroupsForCapacityReservation did not report the group {group_name!r} that the "
        f"reservation was just added to; got groups {group_arns!r}"
    )


def _pick_availability_zone(ec2) -> str:
    resp = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )
    zones = resp["AvailabilityZones"]
    assert zones, "no available Availability Zones in this region"
    return zones[0]["ZoneName"]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(
        f"timed out after {timeout_s}s waiting for {description}; last observed value: {value!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
