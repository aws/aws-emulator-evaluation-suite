"""capacity-provider-update-changes-managed-scaling."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "capacity-provider-update-changes-managed-scaling"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCapacityProvider mutates the managed-scaling config and DescribeCapacityProviders reflects it."""
    env = _setup_asg_capacity_provider(ctx, target_capacity=100, min_step=1, max_step=1)
    ecs = ctx.client("ecs")
    cp_name = env["capacity_provider_name"]

    before_full = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0]
    scaling_before = before_full["autoScalingGroupProvider"]["managedScaling"]
    assert scaling_before["targetCapacity"] == 100, f"expected seeded targetCapacity=100, got {scaling_before['targetCapacity']}"
    assert scaling_before["minimumScalingStepSize"] == 1, f"expected seeded minimumScalingStepSize=1, got {scaling_before['minimumScalingStepSize']}"
    assert scaling_before["maximumScalingStepSize"] == 1, f"expected seeded maximumScalingStepSize=1, got {scaling_before['maximumScalingStepSize']}"

    ecs.update_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={
            "managedScaling": {
                "status": "ENABLED",
                "targetCapacity": 75,
                "minimumScalingStepSize": 2,
                "maximumScalingStepSize": 5,
            }
        },
    )

    after = _poll_until(
        lambda: ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0]["autoScalingGroupProvider"][
            "managedScaling"
        ],
        lambda s: s["targetCapacity"] == 75,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert after["targetCapacity"] == 75, f"expected updated targetCapacity=75, got {after['targetCapacity']}"
    assert after["minimumScalingStepSize"] == 2, f"expected updated minimumScalingStepSize=2, got {after['minimumScalingStepSize']}"
    assert after["maximumScalingStepSize"] == 5, f"expected updated maximumScalingStepSize=5, got {after['maximumScalingStepSize']}"

    # the untouched fields (capacity provider identity, and the sibling autoScalingGroupProvider
    # fields the update request never named) must survive the partial update
    after_full = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0]
    assert after_full["name"] == cp_name, f"expected name to survive the update, got {after_full['name']}"
    assert after_full["status"] == "ACTIVE", f"expected status to remain ACTIVE after the update, got {after_full['status']}"
    assert after_full["capacityProviderArn"] == before_full["capacityProviderArn"], (
        f"expected capacityProviderArn to survive the update, "
        f"before={before_full['capacityProviderArn']!r} after={after_full['capacityProviderArn']!r}"
    )
    assert (
        after_full["autoScalingGroupProvider"]["autoScalingGroupArn"]
        == before_full["autoScalingGroupProvider"]["autoScalingGroupArn"]
    ), "expected the backing ASG binding to survive an update that named only managedScaling"
    assert (
        after_full["autoScalingGroupProvider"]["managedTerminationProtection"]
        == before_full["autoScalingGroupProvider"]["managedTerminationProtection"]
    ), "expected managedTerminationProtection to survive an update that never named it"
    assert (
        after_full["autoScalingGroupProvider"]["managedDraining"]
        == before_full["autoScalingGroupProvider"]["managedDraining"]
    ), "expected managedDraining to survive an update that never named it"


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _setup_asg_capacity_provider(ctx, target_capacity, min_step, max_step):
    from botocore.exceptions import ClientError

    ssm = ctx.client("ssm")
    ec2 = ctx.client("ec2")
    autoscaling = ctx.client("autoscaling")
    ecs = ctx.client("ecs")

    try:
        ami_id = ssm.get_parameter(Name="/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id")["Parameter"]["Value"]
    except ClientError as err:
        raise AssertionError(f"unreachable: cannot resolve the ECS-optimized AMI SSM parameter ({err.response['Error']['Code']})")

    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("unreachable: no shared network VPC subnets available to back the Auto Scaling group")
    subnet_ids = [s["SubnetId"] for s in subnets[:1]]

    lt_name = ctx.unique_name("sim2real-ecs-lt-")
    try:
        lt_id = ec2.create_launch_template(
            LaunchTemplateName=lt_name,
            LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
            TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
        )["LaunchTemplate"]["LaunchTemplateId"]
    except ClientError as err:
        raise AssertionError(f"unreachable: cannot create the launch template backing the capacity provider ({err.response['Error']['Code']})")
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg_name = ctx.unique_name("sim2real-ecs-asg-")
    try:
        autoscaling.create_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
            MinSize=0,
            MaxSize=0,
            DesiredCapacity=0,
            VPCZoneIdentifier=",".join(subnet_ids),
            Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": False}],
        )
    except ClientError as err:
        raise AssertionError(f"unreachable: cannot create the Auto Scaling group backing the capacity provider ({err.response['Error']['Code']})")
    ctx.on_cleanup(lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True))

    asg_arn = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"][0][
        "AutoScalingGroupARN"
    ]

    cp_name = ctx.unique_name("sim2real-asg-cp-")
    try:
        ecs.create_capacity_provider(
            name=cp_name,
            autoScalingGroupProvider={
                "autoScalingGroupArn": asg_arn,
                "managedScaling": {
                    "status": "ENABLED",
                    "targetCapacity": target_capacity,
                    "minimumScalingStepSize": min_step,
                    "maximumScalingStepSize": max_step,
                },
            },
            tags=[{"key": "sim2real", "value": CHECK}],
        )
    except ClientError as err:
        raise AssertionError(f"unreachable: CreateCapacityProvider rejected the Auto Scaling group provider ({err.response['Error']['Code']})")
    ctx.on_cleanup(lambda: ecs.delete_capacity_provider(capacityProvider=cp_name))

    status = _poll_until(
        lambda: ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0]["status"],
        lambda s: s == "ACTIVE",
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert status == "ACTIVE", f"expected the newly created capacity provider to reach ACTIVE, got {status}"

    return {"capacity_provider_name": cp_name, "auto_scaling_group_name": asg_name}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
