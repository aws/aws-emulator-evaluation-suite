"""capacity-provider-update-unknown."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "capacity-provider-update-unknown"
GROUP = "overly-permissive"
SERVICES = ["ecs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateCapacityProvider on a never-created name is refused ClientException with the exact
    message and DescribeCapacityProviders returns no provider for it, while an update of a real
    ASG-backed provider succeeds."""
    ecs = ctx.client("ecs")

    # --- positive control: a real, ASG-backed capacity provider accepts the identical call. ---
    cp_name = _create_shell_capacity_provider(ctx, ecs)
    active = _poll_until(
        lambda: ecs.describe_capacity_providers(capacityProviders=[cp_name])["capacityProviders"][0],
        lambda cp: cp["status"] == "ACTIVE",
        timeout_s=90,
    )
    assert active["status"] == "ACTIVE", f"positive-control capacity provider never became ACTIVE: {active}"

    ecs.update_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={"managedScaling": {"status": "DISABLED"}},
    )

    # --- negative: an update against a name that was never created. ---
    ghost_name = ctx.unique_name("sim2real-behav-ecs-ghost-cp-")
    code, message = _expect_error(
        lambda: ecs.update_capacity_provider(
            name=ghost_name,
            autoScalingGroupProvider={"managedScaling": {"status": "DISABLED"}},
        ),
        ("InvalidParameterException", "ClientException"),
    )
    assert code == "ClientException", code
    assert message == (
        "The specified capacity provider does not exist. Specify a valid name or ARN and try again."
    ), f"unexpected message: {message!r}"

    # --- effect absent: an independent read confirms the ghost name never came into being. ---
    described = ecs.describe_capacity_providers(capacityProviders=[ghost_name])
    assert described.get("capacityProviders", []) == [], (
        f"ghost capacity provider {ghost_name!r} unexpectedly exists after a rejected update: {described}"
    )
    failures = described.get("failures", [])
    assert any(ghost_name in (f.get("arn") or "") or f.get("reason") == "MISSING" for f in failures), (
        f"expected {ghost_name!r} to be reported MISSING, got failures={failures}"
    )


# Codes that mean "the control plane is busy", never "your request was wrong".
_THROTTLE_CODES = (
    "ThrottlingException",
    "Throttling",
    "RequestLimitExceeded",
    "TooManyRequestsException",
)


def _poll_until(fn, pred, *, timeout_s, interval_s=3):
    deadline = time.monotonic() + timeout_s
    while True:
        val = fn()
        if pred(val):
            return val
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={val!r})")
        time.sleep(interval_s)


def _create_shell_capacity_provider(ctx, ecs):
    """An ASG-backed capacity provider with Min/Max/Desired=0 -- no real EC2 instance ever
    launches, so the positive control is cheap."""
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")
    autoscaling = ctx.client("autoscaling")

    ami_id = ssm.get_parameter(
        Name="/aws/service/ecs/optimized-ami/amazon-linux-2023/recommended/image_id"
    )["Parameter"]["Value"]
    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"][0]["ZoneName"]

    lt_name = ctx.unique_name("sim2real-behav-ecs-cpu-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[
            {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": "true"}]}
        ],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    asg_name = ctx.unique_name("sim2real-behav-ecs-cpu-asg-")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        AvailabilityZones=[az],
        Tags=[{"Key": "sim2real", "Value": "true", "PropagateAtLaunch": False}],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(
        lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    )
    asg_arn = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])[
        "AutoScalingGroups"
    ][0]["AutoScalingGroupARN"]

    cp_name = ctx.unique_name("sim2real-behav-ecs-real-cp-")
    ecs.create_capacity_provider(
        name=cp_name,
        autoScalingGroupProvider={
            "autoScalingGroupArn": asg_arn,
            "managedScaling": {"status": "DISABLED"},
            "managedTerminationProtection": "DISABLED",
        },
        tags=[{"key": "sim2real", "value": "true"}],
    )
    ctx.on_cleanup(lambda: ecs.delete_capacity_provider(capacityProvider=cp_name))
    return cp_name


def _expect_error(fn, allowed, attempts: int = 7):
    """Return the (code, message) raised by *fn*, retrying through throttles.

    A success raises: used by overly-permissive checks.
    """
    if isinstance(allowed, str):
        allowed = (allowed,)
    for i in range(attempts):
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            code = err.get("Code")
            if code not in _THROTTLE_CODES:
                return code, err.get("Message")
            time.sleep(min(2.0 * (2**i), 20.0))
            continue
        raise AssertionError(
            f"operation unexpectedly SUCCEEDED with {result!r}; expected one of {allowed}"
        )
    raise AssertionError(f"still throttled after {attempts} attempts; expected {allowed}")


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
