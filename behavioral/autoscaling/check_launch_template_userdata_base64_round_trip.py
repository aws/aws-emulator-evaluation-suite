"""launch-template-userdata-base64-round-trip."""
from __future__ import annotations

import base64

from behavioral_harness import tags

CHECK = "launch-template-userdata-base64-round-trip"
GROUP = "representation"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A base64-encoded UserData blob on a launch template used by an ASG is returned exactly as submitted."""
    ec2 = ctx.client("ec2")
    autoscaling = ctx.client("autoscaling")

    lt_name = ctx.unique_name("sim2real-behav-lt-")
    # Payload includes non-ASCII bytes to make accidental re-encoding/normalization visible.
    payload = b"#!/bin/bash\necho hello-\xe2\x9c\x93-world\n"
    user_data_b64 = base64.b64encode(payload).decode("ascii")

    resp = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={
            "ImageId": _valid_ami(ctx),
            "InstanceType": "t3.micro",
            "UserData": user_data_b64,
        },
        TagSpecifications=[
            {
                "ResourceType": "launch-template",
                "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
            }
        ],
    )
    lt_id = resp["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    versions = ec2.describe_launch_template_versions(
        LaunchTemplateId=lt_id, Versions=["$Latest"]
    )["LaunchTemplateVersions"]
    assert len(versions) == 1
    got_user_data = versions[0]["LaunchTemplateData"]["UserData"]
    assert got_user_data == user_data_b64, (
        f"UserData drifted on round-trip: sent {user_data_b64!r}, got {got_user_data!r}"
    )
    assert base64.b64decode(got_user_data) == payload

    # Tie the template to a real Auto Scaling group to confirm the ASG references the
    # exact same template/version whose data we just validated.
    asg_name = ctx.unique_name("sim2real-behav-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        AvailabilityZones=[ctx.network().availability_zones[0]],
        Tags=[
            {
                "ResourceId": asg_name,
                "ResourceType": "auto-scaling-group",
                "Key": "sim2real:managed",
                "Value": "true",
                "PropagateAtLaunch": False,
            }
        ],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [ctx.network().availability_zones[0]]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(
            AutoScalingGroupName=asg_name, ForceDelete=True
        )
    )
    group = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]
    assert group["LaunchTemplate"]["LaunchTemplateId"] == lt_id


def _valid_ami(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


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
