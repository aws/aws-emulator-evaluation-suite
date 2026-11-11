"""update-capacity-provider-changes-managed-scaling."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-capacity-provider-changes-managed-scaling"
GROUP = "state-machine"
SERVICES = ["ecs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateCapacityProvider mutates the autoScalingGroupProvider.managedScaling config and
    DescribeCapacityProviders reflects the new targetCapacity/step sizes."""
    ecs = ctx.client("ecs")
    ec2 = ctx.client("ec2")
    autoscaling = ctx.client("autoscaling")
    ssm = ctx.client("ssm")

    subnet_id = ctx.network().subnet_ids[0]
    ami_id = ssm.get_parameter(
        Name="/aws/service/ecs/optimized-ami/amazon-linux-2/recommended/image_id"
    )["Parameter"]["Value"]

    lt_name = ctx.unique_name("sim2real-behav-cp-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": "true"}]}
        ],
    )
    ctx.on_cleanup(
        lambda: _ignore_client_error(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))
    )

    asg_name = ctx.unique_name("sim2real-behav-cp-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        Tags=[
            {
                "Key": "sim2real",
                "Value": "true",
                "ResourceId": asg_name,
                "ResourceType": "auto-scaling-group",
                "PropagateAtLaunch": False,
            }
        ],
    )
    ctx.on_cleanup(
        lambda: _ignore_client_error(
            lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
        )
    )
    asg_arn = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]["AutoScalingGroupARN"]

    cp_name = ctx.unique_name("sim2real-behav-cp-")
    created = ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={
            "autoScalingGroupArn": asg_arn,
            "managedScaling": {
                "status": "ENABLED",
                "targetCapacity": 80,
                "minimumScalingStepSize": 1,
                "maximumScalingStepSize": 1,
            },
            "managedTerminationProtection": "DISABLED",
        },
        tags=[{"key": "sim2real", "value": "true"}],
    )["capacityProvider"]
    cp_arn = created["capacityProviderArn"]
    ctx.on_cleanup(
        lambda: _ignore_client_error(lambda: ecs.delete_capacity_provider(capacityProvider=cp_arn))
    )
    created_target = created["autoScalingGroupProvider"]["managedScaling"]["targetCapacity"]
    assert created_target == 80, f"expected freshly-created targetCapacity=80, got {created_target}"

    ecs.update_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={
            "managedScaling": {
                "status": "ENABLED",
                "targetCapacity": 50,
                "minimumScalingStepSize": 1,
                "maximumScalingStepSize": 2,
            }
        },
    )

    described = _poll_until(
        lambda: ecs.describe_capacity_providers(capacityProviders=[cp_arn])["capacityProviders"][0],
        lambda cp: cp["autoScalingGroupProvider"]["managedScaling"]["targetCapacity"] == 50,
        timeout_s=60,
        interval_s=3,
    )
    described_scaling = described["autoScalingGroupProvider"]["managedScaling"]
    assert described_scaling["targetCapacity"] == 50, (
        f"expected DescribeCapacityProviders to reflect updated targetCapacity=50, got {described_scaling['targetCapacity']}"
    )
    assert described_scaling["maximumScalingStepSize"] == 2, (
        f"expected DescribeCapacityProviders to reflect updated maximumScalingStepSize=2, got {described_scaling['maximumScalingStepSize']}"
    )


def _ignore_client_error(fn):
    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if (
            err["Code"] not in ("ClusterNotFoundException", "InvalidLaunchTemplateId.NotFound")
            and not (err["Code"] == "ClientException" and "The specified capacity provider does not exist" in err.get("Message", ""))
            and not (err["Code"] == "ValidationError" and "not found" in err.get("Message", ""))
        ):
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
