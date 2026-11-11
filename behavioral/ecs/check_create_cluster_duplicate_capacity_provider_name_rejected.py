"""create-cluster-duplicate-capacity-provider-name-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-cluster-duplicate-capacity-provider-name-rejected"
GROUP = "negative-classes"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateCapacityProvider with an existing provider's name is rejected as a name conflict
    (not a malformed-ASG InvalidParameterException), leaving the original's ASG unchanged."""
    ecs = ctx.client("ecs")
    autoscaling = ctx.client("autoscaling")
    ami_id = _latest_ecs_optimized_ami(ctx)
    subnet_id = _default_subnet(ctx)

    lt_name = ctx.unique_name("sim2real-dupcp-lt-")
    ec2 = ctx.client("ec2")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": lt_name}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-dupcp-asg-")
    asg_arn = _create_empty_asg(ctx, autoscaling, asg_name, lt_name, subnet_id)

    cp_name = ctx.unique_name("sim2real-dupcp-")
    ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={"autoScalingGroupArn": asg_arn, "managedScaling": {"status": "DISABLED"}},
        tags=[{"key": "sim2real", "value": cp_name}],
    )
    ctx.on_cleanup(lambda: ecs.delete_capacity_provider(capacityProvider=cp_name))

    described = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"]
    assert len(described) == 1 and described[0]["status"] == "ACTIVE", (
        f"expected exactly one ACTIVE capacity provider named {cp_name!r}, got {described!r}"
    )

    # A different, syntactically valid ASG, so the rejection can only be the name conflict.
    asg2_name = ctx.unique_name("sim2real-dupcp-asg2-")
    asg2_arn = _create_empty_asg(ctx, autoscaling, asg2_name, lt_name, subnet_id)

    code, message = _error(
        lambda: ecs.create_capacity_provider(
            name=cp_name,
            autoScalingGroupProvider={"autoScalingGroupArn": asg2_arn, "managedScaling": {"status": "DISABLED"}},
        )
    )
    assert code == "ClientException", f"expected ClientException, got {code!r}"
    expected_message = (
        "The specified capacity provider already exists. To change the configuration of an "
        "existing capacity provider, update the capacity provider."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the original capacity provider's ASG binding is unchanged.
    described = ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0]
    assert described["autoScalingGroupProvider"]["autoScalingGroupArn"] == asg_arn, (
        "the existing capacity provider's ASG binding changed despite the rejected duplicate create"
    )

    # Positive control: a genuinely new, unused name succeeds.
    cp_name_2 = ctx.unique_name("sim2real-dupcp-b-")
    ecs.create_capacity_provider(
        name=cp_name_2,
        autoScalingGroupProvider={"autoScalingGroupArn": asg2_arn, "managedScaling": {"status": "DISABLED"}},
        tags=[{"key": "sim2real", "value": cp_name_2}],
    )
    ctx.on_cleanup(lambda: ecs.delete_capacity_provider(capacityProvider=cp_name_2))
    described2 = ecs.describe_capacity_providers(capacityProviders=[cp_name_2])["capacityProviders"]
    assert len(described2) == 1 and described2[0]["status"] == "ACTIVE", (
        f"expected the positive-control capacity provider {cp_name_2!r} to be ACTIVE, got {described2!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _latest_ecs_optimized_ami(ctx):
    ssm = ctx.client("ssm")
    value = ssm.get_parameter(Name="/aws/service/ecs/optimized-ami/amazon-linux-2/recommended")["Parameter"]["Value"]
    return json.loads(value)["image_id"]


def _default_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to create an Auto Scaling group")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("no network subnet available to create an Auto Scaling group")
    return subnets[0]["SubnetId"]


def _create_empty_asg(ctx, autoscaling, asg_name, lt_name, subnet_id):
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
        NewInstancesProtectedFromScaleIn=True,
        Tags=[
            {
                "ResourceId": asg_name,
                "ResourceType": "auto-scaling-group",
                "Key": "sim2real",
                "Value": asg_name,
                "PropagateAtLaunch": False,
            }
        ],
    )

    def _delete_asg():
        autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
        _poll_until(
            lambda: _asg_exists(autoscaling, asg_name),
            lambda exists: not exists,
            timeout_s=60,
            interval_s=3,
            description=f"Auto Scaling group {asg_name} to be deleted",
        )

    ctx.on_cleanup(_delete_asg)
    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
    return groups[0]["AutoScalingGroupARN"]


def _asg_exists(autoscaling, asg_name):
    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
    return len(groups) > 0


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out waiting for {description} (last value: {result!r})")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
