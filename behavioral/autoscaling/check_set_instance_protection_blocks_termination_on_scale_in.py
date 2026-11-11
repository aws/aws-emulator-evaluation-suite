"""set-instance-protection-blocks-termination-on-scale-in."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "set-instance-protection-blocks-termination-on-scale-in"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """An instance with SetInstanceProtection(ProtectedFromScaleIn=True) enabled must never
    be the one selected and terminated when the group scales in -- the scale-in logic must
    treat protection as a hard exclusion, not a soft preference."""
    asg = ctx.client("autoscaling")
    subnet_id = _get_default_subnet(ctx)
    ami_id = _get_al2_ami(ctx)
    lt_name = _create_launch_template(ctx, ami_id=ami_id)
    group_name = ctx.unique_name("sim2real-behav-asg-")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=group_name,
        LaunchTemplate={"LaunchTemplateName": lt_name},
        MinSize=2,
        MaxSize=2,
        DesiredCapacity=2,
        VPCZoneIdentifier=subnet_id,
        NewInstancesProtectedFromScaleIn=False,
        Tags=[
            {
                "Key": "sim2real:managed",
                "Value": "true",
                "PropagateAtLaunch": True,
                "ResourceId": group_name,
                "ResourceType": "auto-scaling-group",
            }
        ],
    )
    ctx.on_cleanup(lambda: _delete_asg_force(ctx, group_name))

    def _instances_probe():
        return asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])[
            "AutoScalingGroups"
        ][0]["Instances"]

    instances = _poll_until(
        _instances_probe,
        lambda ins: len(ins) == 2 and all(i["LifecycleState"] == "InService" for i in ins),
        timeout_s=420,
        interval_s=10,
    )
    ids = sorted(i["InstanceId"] for i in instances)
    protected_id, other_id = ids[0], ids[1]

    asg.set_instance_protection(
        InstanceIds=[protected_id], AutoScalingGroupName=group_name, ProtectedFromScaleIn=True
    )

    protection_state = {
        i["InstanceId"]: i["ProtectedFromScaleIn"]
        for i in asg.describe_auto_scaling_instances(InstanceIds=[protected_id, other_id])[
            "AutoScalingInstances"
        ]
    }
    assert protection_state[protected_id] is True, (
        f"expected {protected_id!r} ProtectedFromScaleIn=True, got {protection_state[protected_id]!r}"
    )
    assert protection_state[other_id] is False, (
        f"expected {other_id!r} ProtectedFromScaleIn=False, got {protection_state[other_id]!r}"
    )

    # Scaling in to 1 requires the group's MinSize to allow it; lower MinSize first so the
    # SetDesiredCapacity call below isn't rejected by validation against the original MinSize=2.
    asg.update_auto_scaling_group(AutoScalingGroupName=group_name, MinSize=1)

    asg.set_desired_capacity(AutoScalingGroupName=group_name, DesiredCapacity=1, HonorCooldown=False)

    remaining = _poll_until(
        _instances_probe,
        lambda ins: len(ins) == 1,
        timeout_s=420,
        interval_s=10,
    )
    assert remaining[0]["InstanceId"] == protected_id, (
        f"scale-in terminated the protected instance {protected_id!r}; "
        f"surviving instance was {remaining[0]['InstanceId']!r} instead"
    )


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _get_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


def _get_default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets")
    return subnets[0]["SubnetId"]


def _create_launch_template(ctx, ami_id: str, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "ImageId": ami_id,
            "InstanceType": instance_type,
            "TagSpecifications": [
                {
                    "ResourceType": "instance",
                    "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
                },
                {
                    "ResourceType": "volume",
                    "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
                },
            ],
        },
        TagSpecifications=[
            {
                "ResourceType": "launch-template",
                "Tags": [{"Key": "sim2real:managed", "Value": "true"}],
            }
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _delete_asg_force(ctx, name: str) -> None:
    asg = ctx.client("autoscaling")
    for _ in range(30):
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("ScalingActivityInProgress", "ResourceContention", "ResourceInUse"):
                time.sleep(5)
                continue
            if code == "ValidationError":
                return
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
