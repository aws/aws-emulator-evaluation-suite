"""standby-instances-excluded-from-health-driven-replacement."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "standby-instances-excluded-from-health-driven-replacement"
GROUP = "state-machine"
SERVICES = ["autoscaling"]

_MANAGED_TAGS = {"sim2real": "as-depth", "sim2real:managed": "true"}


@tags("axis:negative-delivery", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Standby instance is excluded from health-driven replacement; an InService twin marked
    Unhealthy at the same time is replaced, and ExitStandby restores normal handling."""
    asg = ctx.client("autoscaling")
    subnet = _default_subnet(ctx)
    ami_id = _al2023_ami(ctx)
    lt_id = _create_launch_template(ctx, ami_id)

    group_name = ctx.unique_name("sim2real-behav-asg-")
    _create_asg(ctx, group_name, lt_id, min_size=1, max_size=2, desired=2, subnet_id=subnet["subnet_id"])

    in_service = _poll(
        lambda: [i["InstanceId"] for i in _group_instances(ctx, group_name) if i["LifecycleState"] == "InService"],
        lambda ids: len(ids) == 2,
        timeout_s=300,
        interval_s=5,
        description="the group reached 2 InService instances",
    )
    standby_id, control_id = sorted(in_service)

    asg.enter_standby(
        InstanceIds=[standby_id], AutoScalingGroupName=group_name, ShouldDecrementDesiredCapacity=True
    )
    standby_state = _poll(
        lambda: _find_instance(ctx, group_name, standby_id),
        lambda i: i is not None and i["LifecycleState"] == "Standby",
        timeout_s=120,
        interval_s=4,
        description=f"instance {standby_id} entered Standby after EnterStandby",
    )
    assert standby_state is not None and standby_state["LifecycleState"] == "Standby", (
        f"instance never entered Standby after EnterStandby: {standby_state}"
    )
    group_after_standby = _describe_group(ctx, group_name)
    assert group_after_standby["DesiredCapacity"] == 1, (
        f"DesiredCapacity did not decrement on EnterStandby: {group_after_standby['DesiredCapacity']}"
    )

    # Break exactly one thing on both instances, in the same breath: only lifecycle state differs.
    for instance_id in (standby_id, control_id):
        asg.set_instance_health(InstanceId=instance_id, HealthStatus="Unhealthy", ShouldRespectGracePeriod=False)
    control_health = _poll(
        lambda: _health_of(ctx, group_name, control_id),
        lambda h: h == "Unhealthy",
        timeout_s=120,
        interval_s=4,
        description=f"the control instance {control_id} records HealthStatus Unhealthy",
    )
    assert control_health == "Unhealthy", (
        f"the Unhealthy mark never landed on the control instance, so its replacement below is not "
        f"evidence of anything: {control_health!r}"
    )

    # The barrier: the InService twin's replacement proves health-driven replacement is active,
    # and its observed latency bounds the absence asserted on the Standby twin next.
    control_after = _poll(
        lambda: [i["InstanceId"] for i in _group_instances(ctx, group_name) if i["LifecycleState"] == "InService"],
        lambda ids: len(ids) == 1 and ids[0] != control_id,
        timeout_s=1200,
        interval_s=15,
        description=f"health-driven replacement replaced the control instance {control_id}",
    )
    assert control_id not in control_after, (
        f"the InService control instance was never replaced by health-driven replacement, so the "
        f"standby instance's unchanged state below is not evidence of exclusion: {control_after!r}"
    )
    old_control_state = _poll(
        lambda: _ec2_state(ctx, control_id),
        lambda s: s in ("shutting-down", "terminated"),
        timeout_s=300,
        interval_s=10,
        description=f"the replaced control instance {control_id} was really terminated",
    )
    assert old_control_state in ("shutting-down", "terminated"), (
        f"the control instance was marked replaced but never terminated: {old_control_state!r}"
    )

    # Only now check the standby twin: it was Unhealthy for at least as long as the control
    # instance's real replacement took, and it must be untouched.
    standby_after = _find_instance(ctx, group_name, standby_id)
    assert standby_after is not None and standby_after["LifecycleState"] == "Standby", (
        f"the standby instance was moved out of Standby by health-driven replacement while marked "
        f"Unhealthy: {standby_after}"
    )
    assert _ec2_state(ctx, standby_id) == "running", (
        f"the standby instance's EC2 instance was terminated even though it is excluded from "
        f"health-driven replacement: {_ec2_state(ctx, standby_id)!r}"
    )

    # Health status persists across ExitStandby, so restore Healthy while still in Standby;
    # otherwise AWS would terminate this instance as unhealthy once it is back InService.
    asg.set_instance_health(InstanceId=standby_id, HealthStatus="Healthy")
    asg.exit_standby(InstanceIds=[standby_id], AutoScalingGroupName=group_name)

    back_in_service = _poll(
        lambda: _find_instance(ctx, group_name, standby_id),
        lambda i: i is not None and i["LifecycleState"] == "InService",
        timeout_s=180,
        interval_s=5,
        description=f"instance {standby_id} returned to InService after ExitStandby",
    )
    assert back_in_service is not None and back_in_service["LifecycleState"] == "InService", (
        f"instance never returned to InService after ExitStandby: {back_in_service}"
    )
    group_after_exit = _describe_group(ctx, group_name)
    assert group_after_exit["DesiredCapacity"] == 2, (
        f"DesiredCapacity did not re-increment on ExitStandby: {group_after_exit['DesiredCapacity']}"
    )


def _poll(probe, predicate, *, timeout_s, interval_s=3.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


def _describe_group(ctx, group_name: str) -> dict:
    asg = ctx.client("autoscaling")
    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])["AutoScalingGroups"]
    assert groups, f"group {group_name} not found"
    return groups[0]


def _group_instances(ctx, group_name: str) -> list[dict]:
    return _describe_group(ctx, group_name)["Instances"]


def _find_instance(ctx, group_name: str, instance_id: str):
    return next((i for i in _group_instances(ctx, group_name) if i["InstanceId"] == instance_id), None)


def _health_of(ctx, group_name: str, instance_id: str) -> str | None:
    instance = _find_instance(ctx, group_name, instance_id)
    return instance["HealthStatus"] if instance is not None else None


def _ec2_state(ctx, instance_id: str) -> str:
    ec2 = ctx.client("ec2")
    reservations = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"]
    assert reservations, f"instance {instance_id} not found in EC2"
    return reservations[0]["Instances"][0]["State"]["Name"]


def _default_subnet(ctx) -> dict[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    assert subnets, f"no subnets found in VPC {vpc_id}"
    subnet = subnets[0]
    return {"vpc_id": vpc_id, "subnet_id": subnet["SubnetId"]}


def _al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    try:
        name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        return ssm.get_parameter(Name=name)["Parameter"]["Value"]
    except Exception:
        ec2 = ctx.client("ec2")
        images = ec2.describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
                {"Name": "state", "Values": ["available"]},
            ],
        )["Images"]
        assert images, "no al2023 AMI found owned by amazon"
        images.sort(key=lambda im: im["CreationDate"], reverse=True)
        return images[0]["ImageId"]


def _create_launch_template(ctx, ami_id: str, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    tags_kv = [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]
    resp = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={
            "ImageId": ami_id,
            "InstanceType": instance_type,
            "TagSpecifications": [
                {"ResourceType": "instance", "Tags": tags_kv},
                {"ResourceType": "volume", "Tags": tags_kv},
            ],
        },
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": tags_kv}],
    )
    lt_id = resp["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _create_asg(ctx, name: str, lt_id: str, min_size: int, max_size: int, desired: int, subnet_id: str, **kwargs):
    asg = ctx.client("autoscaling")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateId": lt_id},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": k, "Value": v, "PropagateAtLaunch": True} for k, v in _MANAGED_TAGS.items()],
        **kwargs,
    )

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
        except ClientError as err:
            error = err.response["Error"]
            if error["Code"] != "ValidationError" or "not found" not in error.get("Message", ""):
                raise

    ctx.on_cleanup(_cleanup)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
