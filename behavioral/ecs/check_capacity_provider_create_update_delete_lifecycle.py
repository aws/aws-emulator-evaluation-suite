"""capacity-provider-create-update-delete-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "capacity-provider-create-update-delete-lifecycle"
GROUP = 'capacity-provider'
SERVICES = ['ecs']


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises:
    accepting input that AWS refuses must not be reported as a mere error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(fn, pred, *, timeout_s, interval_s=3):
    deadline = time.monotonic() + timeout_s
    while True:
        val = fn()
        if pred(val):
            return val
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={val!r})")
        time.sleep(interval_s)


def _create_shell_asg(ctx):
    """Create a real ASG-backed launch template/ASG with Min/Max/Desired=0 — no real
    EC2 instances ever launch, so the CapacityProvider CRUD state machine can be
    exercised cheaply against a genuine (not merely well-formed) ASG ARN."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    autoscaling = ctx.client("autoscaling")

    ami_id = ssm.get_parameter(
        Name="/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id"
    )["Parameter"]["Value"]
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"][0]["ZoneName"]

    lt_name = ctx.unique_name("sim2real-ecs-cp-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-ecs-cp-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        AvailabilityZones=[az],
        Tags=[{"Key": "sim2real", "Value": CHECK, "ResourceId": asg_name, "ResourceType": "auto-scaling-group"}],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )
    return autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]["AutoScalingGroupARN"]


def _create_shell_capacity_provider(ctx, ecs, asg_arn):
    cp_name = ctx.unique_name("sim2real-ecs-cp-")
    ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={
            "autoScalingGroupArn": asg_arn,
            "managedScaling": {"status": "DISABLED"},
            "managedTerminationProtection": "DISABLED",
        },
        tags=[{"key": "sim2real", "value": CHECK}],
    )
    ctx.on_cleanup(lambda: ecs.delete_capacity_provider(capacityProvider=cp_name))
    return cp_name


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCapacityProvider -> ACTIVE -> UpdateCapacityProvider -> Delete
    (DEPROVISIONING/INACTIVE); the reserved built-in name "FARGATE" is rejected on create.
    """
    ecs = ctx.client("ecs")

    try:
        asg_arn = _create_shell_asg(ctx)
    except ClientError as exc:
        raise AssertionError(f"could not provision a shell ASG for this check: {exc}") from None

    # The ASG ARN is real, so a rejection here is due to the reserved name alone,
    # not to a nonexistent ASG reference.
    code, message = _error(
        lambda: ecs.create_capacity_provider(
            name="FARGATE",
            autoScalingGroupProvider={"autoScalingGroupArn": asg_arn},
        )
    )
    assert code == "ClientException", (
        f"expected an error creating a capacity provider named the reserved 'FARGATE', got {code}"
    )
    assert message == (
        "The specified capacity provider name is invalid. Up to 255 characters are allowed, "
        "including letters (upper and lowercase), numbers, underscores, and hyphens. The name "
        'cannot be prefixed with "aws", "ecs", or "fargate". Specify a valid name and try again.'
    ), f"reserved name: unexpected message {message!r}"

    try:
        cp_name = _create_shell_capacity_provider(ctx, ecs, asg_arn)
    except AssertionError:
        raise
    except ClientError as exc:
        raise AssertionError(f"could not provision a shell ASG-backed capacity provider: {exc}") from None

    described = _poll_until(
        lambda: ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0],
        lambda cp: cp["status"] == "ACTIVE",
        timeout_s=90,
    )
    assert described["status"] == "ACTIVE", f"expected ACTIVE, got {described['status']!r}"
    assert described["autoScalingGroupProvider"]["managedScaling"]["status"] == "DISABLED", (
        f"expected managedScaling DISABLED as created, got {described['autoScalingGroupProvider']['managedScaling']!r}"
    )

    ecs.update_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={"managedScaling": {"status": "ENABLED", "targetCapacity": 100}},
    )
    updated = _poll_until(
        lambda: ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0],
        lambda cp: cp["autoScalingGroupProvider"]["managedScaling"]["status"] == "ENABLED",
        timeout_s=90,
    )
    assert updated["autoScalingGroupProvider"]["managedScaling"]["status"] == "ENABLED", (
        f"expected managedScaling ENABLED after update, got {updated['autoScalingGroupProvider']['managedScaling']!r}"
    )

    del_resp = ecs.delete_capacity_provider(capacityProvider=cp_name)
    assert del_resp["capacityProvider"]["status"] in ("DEPROVISIONING", "INACTIVE"), (
        f"expected DEPROVISIONING/INACTIVE right after delete, got {del_resp['capacityProvider']['status']}"
    )

    final = _poll_until(
        lambda: ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0],
        lambda cp: cp["status"] == "INACTIVE",
        timeout_s=90,
    )
    assert final["status"] == "INACTIVE", f"expected INACTIVE after delete settled, got {final['status']!r}"


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
