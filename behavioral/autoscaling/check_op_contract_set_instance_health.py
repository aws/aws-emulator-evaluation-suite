"""op-contract-set-instance-health."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "op-contract-set-instance-health"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetInstanceHealth(Unhealthy) flips the instance's reported HealthStatus and causes Amazon
    EC2 Auto Scaling to move it into Terminating for replacement; an invalid HealthStatus value
    is rejected and the instance's health is left unchanged."""
    autoscaling = ctx.client("autoscaling")
    ami_id = _resolve_ami(ctx)
    subnet_id = _default_subnet(ctx)
    lt_id = _create_launch_template(ctx, ami_id)
    name = ctx.unique_name("sim2real-behav-insthealth-")
    _create_asg(ctx, name, lt_id, subnet_id, min_size=0, max_size=2, desired=1)

    instances = _poll_until(
        lambda: _group_instances(ctx, name),
        lambda ins: len(ins) == 1 and ins[0]["LifecycleState"] == "InService",
        timeout_s=300.0,
        interval_s=10.0,
    )
    instance_id = instances[0]["InstanceId"]
    assert instances[0]["HealthStatus"] == "Healthy", (
        f"expected freshly-launched instance {instance_id!r} to report Healthy, "
        f"got {instances[0]['HealthStatus']!r}"
    )

    autoscaling.set_instance_health(InstanceId=instance_id, HealthStatus="Unhealthy", ShouldRespectGracePeriod=False)

    _poll_until(
        lambda: _group_instances(ctx, name),
        lambda ins: any(i["InstanceId"] == instance_id and i["HealthStatus"] == "Unhealthy" for i in ins),
        timeout_s=60.0,
        interval_s=5.0,
    )

    # Amazon EC2 Auto Scaling detects the unhealthy instance and schedules it for termination
    # and replacement.
    _poll_until(
        lambda: _group_instances(ctx, name),
        lambda ins: any(
            i["InstanceId"] == instance_id and i["LifecycleState"].startswith("Terminating") for i in ins
        )
        or not any(i["InstanceId"] == instance_id for i in ins),
        timeout_s=240.0,
        interval_s=10.0,
    )

    # Error boundary: an invalid HealthStatus enum value is rejected, and it does not alter any
    # instance's reported health.
    healthy_snapshot = {i["InstanceId"]: i["HealthStatus"] for i in _group_instances(ctx, name)}
    code, message = _error(
        lambda: autoscaling.set_instance_health(InstanceId=instance_id, HealthStatus="Sick")
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected_message = "Valid instance health states are: [Healthy, Unhealthy]."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    after_snapshot = {i["InstanceId"]: i["HealthStatus"] for i in _group_instances(ctx, name)}
    assert after_snapshot == healthy_snapshot, (
        f"rejected SetInstanceHealth(HealthStatus='Sick') must not change any instance's "
        f"reported health, expected {healthy_snapshot!r}, got {after_snapshot!r}"
    )


def _error(fn):
    """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _resolve_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    param_name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    return ssm.get_parameter(Name=param_name)["Parameter"]["Value"]


def _default_subnet(ctx) -> str:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region")
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpcs[0]["VpcId"]]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("no subnets available in the shared network")
    return subnets[0]["SubnetId"]


def _create_launch_template(ctx, ami_id: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_asg(ctx, name: str, lt_id: str, subnet_id: str, min_size: int, max_size: int, desired: int) -> None:
    autoscaling = ctx.client("autoscaling")
    autoscaling.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "$Latest"},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
    )
    ctx.on_cleanup(lambda: autoscaling.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True))


def _group_instances(ctx, name: str) -> list[dict[str, Any]]:
    autoscaling = ctx.client("autoscaling")
    groups = autoscaling.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]
    return groups[0]["Instances"] if groups else []


def _poll_until(probe, predicate, *, timeout_s=300.0, interval_s=10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
