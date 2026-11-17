"""fleet-maintain-target-capacity-scaling-launches-and-terminates-the-instance."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fleet-maintain-target-capacity-scaling-launches-and-terminates-the-instance"
GROUP = "fleet"
SERVICES = ["ec2"]

_TYPE = "t3.micro"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Raising a maintain-type EC2 Fleet's target capacity from 0 to 1 launches a real
    instance that DescribeFleetInstances names, and lowering it back to 0 with
    ExcessCapacityTerminationPolicy='termination' terminates that same instance."""
    ec2 = ctx.client("ec2")
    net = ctx.network()

    offered = {
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone", Filters=[{"Name": "instance-type", "Values": [_TYPE]}]
        )["InstanceTypeOfferings"]
    }
    usable = [az for az in net.availability_zones if az in offered]
    assert usable, f"no zone of the run's network offers {_TYPE!r}: {net.availability_zones!r}"
    subnet_id = net.subnets[usable[0]]

    ami_id = _latest_al2023_ami(ec2)
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": _TYPE, "SecurityGroupIds": [net.security_group_id]},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "Name", "Value": lt_name}]}],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    fleet_name = ctx.unique_name("sim2real-behav-fleet-")
    fleet_id = ec2.create_fleet(
        Type="maintain",
        LaunchTemplateConfigs=[
            {
                "LaunchTemplateSpecification": {"LaunchTemplateId": lt_id, "Version": "$Latest"},
                "Overrides": [{"SubnetId": subnet_id}],
            }
        ],
        TargetCapacitySpecification={"TotalTargetCapacity": 0, "DefaultTargetCapacityType": "on-demand"},
        ExcessCapacityTerminationPolicy="termination",
        TagSpecifications=[{"ResourceType": "fleet", "Tags": [{"Key": "Name", "Value": fleet_name}]}],
    )["FleetId"]
    ctx.on_cleanup(lambda: ec2.delete_fleets(FleetIds=[fleet_id], TerminateInstances=True))

    assert _fleet_instance_ids(ec2, fleet_id) == set(), (
        "a freshly created fleet with TotalTargetCapacity=0 must start with no instances"
    )

    ec2.modify_fleet(FleetId=fleet_id, TargetCapacitySpecification={"TotalTargetCapacity": 1})

    launched = _poll_until(
        lambda: _fleet_instance_ids(ec2, fleet_id),
        lambda ids: len(ids) == 1,
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert len(launched) == 1, f"expected exactly one instance after raising capacity to 1, got {launched!r}"
    instance_id = next(iter(launched))

    state = _poll_until(
        lambda: _instance_state(ec2, instance_id),
        lambda s: s in ("running", "terminated", "__gone__"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert state == "running", f"expected the fleet-launched instance to reach 'running', got {state!r}"

    ec2.modify_fleet(FleetId=fleet_id, TargetCapacitySpecification={"TotalTargetCapacity": 0})

    remaining = _poll_until(
        lambda: _fleet_instance_ids(ec2, fleet_id),
        lambda ids: ids == set(),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert remaining == set(), f"expected no instances once capacity was lowered to 0, got {remaining!r}"

    final_state = _poll_until(
        lambda: _instance_state(ec2, instance_id),
        lambda s: s in ("terminated", "__gone__"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert final_state in ("terminated", "__gone__"), (
        f"expected the instance to be terminated once excess capacity was reclaimed, got {final_state!r}"
    )


def _fleet_instance_ids(ec2, fleet_id) -> set:
    ids = set()
    kwargs = {"FleetId": fleet_id}
    while True:
        page = ec2.describe_fleet_instances(**kwargs)
        ids.update(i["InstanceId"] for i in page["ActiveInstances"])
        token = page.get("NextToken")
        if not token:
            return ids
        kwargs["NextToken"] = token


def _instance_state(ec2, instance_id):
    try:
        reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidInstanceID.NotFound":
            return "__gone__"
        raise
    if not reservations or not reservations[0]["Instances"]:
        return "__gone__"
    return reservations[0]["Instances"][0]["State"]["Name"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _latest_al2023_ami(ec2) -> str:
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no amazon-owned al2023 AMIs found in this region")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
