"""op-contract-deleteCapacityProvider."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-deleteCapacityProvider"
GROUP = "error-semantics"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteCapacityProvider deprovisions an unassociated provider and rejects an unknown name."""
    ecs = ctx.client("ecs")
    autoscaling = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(Filters=[{"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"][0]["ZoneName"]
    ami_id = _latest_al2023_ami(ec2)
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"InstanceType": "t3.micro", "ImageId": ami_id},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        AvailabilityZones=[az],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )
    asg_arn = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]["AutoScalingGroupARN"]

    cp_name = ctx.unique_name("sim2real-behav-cp-")
    ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={
            "autoScalingGroupArn": asg_arn,
            "managedScaling": {"status": "DISABLED"},
        },
    )

    resp = ecs.delete_capacity_provider(capacityProvider=cp_name)
    assert resp["capacityProvider"]["name"] == cp_name, (
        f"expected DeleteCapacityProvider to echo back {cp_name!r}, "
        f"got {resp['capacityProvider'].get('name')!r}"
    )
    assert resp["capacityProvider"]["status"] in ("DEPROVISIONING", "INACTIVE"), (
        f"expected DEPROVISIONING or INACTIVE immediately after delete, "
        f"got {resp['capacityProvider'].get('status')!r}"
    )

    deadline = time.monotonic() + 60
    final_status = None
    while time.monotonic() < deadline:
        described = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"]
        final_status = described[0]["status"] if described else None
        if final_status == "INACTIVE":
            break
        time.sleep(3)
    assert final_status == "INACTIVE", f"capacity provider never reached INACTIVE, last={final_status}"

    err, message = _error(lambda: ecs.delete_capacity_provider(capacityProvider="sim2real-does-not-exist-cp"))
    assert err == "ClientException", f"expected ClientException, got {err}"
    expected_message = 'Failed to get info for provided CapacityProvider'
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _latest_al2023_ami(ec2) -> str:
    """The launch template must carry a valid AMI: CreateAutoScalingGroup rejects a
    launch template without a resolvable ImageId ("You must use a valid fully-formed
    launch template...") before ECS ever sees the ASG."""
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises: an
    emulator accepting a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _network_zone_subnets(ctx, zones) -> str:
    """The shared network's subnets in `zones`, comma-separated for VPCZoneIdentifier."""
    by_zone = ctx.network().subnets
    missing = [z for z in zones if z not in by_zone]
    if missing:
        raise AssertionError(f"the run's shared network has no subnet in {missing}")
    return ",".join(by_zone[z] for z in zones)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
