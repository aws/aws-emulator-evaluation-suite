"""suspend-resume-processes-blocks-specific-actions."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "suspend-resume-processes-blocks-specific-actions"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Suspending the Launch process prevents SetDesiredCapacity from actually adding
    instances; ResumeProcesses lets the group converge to the pending desired capacity."""
    asg = ctx.client("autoscaling")
    subnet = _default_subnet(ctx)
    ami_id = _al2023_ami(ctx)

    group_name = ctx.unique_name("sim2real-behav-asg-")
    lt_id = _create_launch_template(ctx, ami_id, tag_value=group_name)
    _create_asg(ctx, group_name, lt_id, min_size=0, max_size=3, desired=0, subnet_id=subnet["subnet_id"])

    asg.suspend_processes(AutoScalingGroupName=group_name, ScalingProcesses=["Launch"])
    suspended = _describe_group(ctx, group_name)["SuspendedProcesses"]
    assert any(p["ProcessName"] == "Launch" for p in suspended), (
        f"Launch process not reflected in SuspendedProcesses: {suspended}"
    )

    asg.set_desired_capacity(AutoScalingGroupName=group_name, DesiredCapacity=2, HonorCooldown=False)

    group_after_set = _describe_group(ctx, group_name)
    assert group_after_set["DesiredCapacity"] == 2, "DesiredCapacity should update even while Launch is suspended"

    # Give the group a bounded window to (not) launch instances while Launch is suspended, and
    # corroborate the ASG's own view with an independent read at EC2 (a different service, keyed
    # off the launch-template tag rather than the ASG's Instances field) so a target that merely
    # omits the instance from DescribeAutoScalingGroups without withholding the actual launch
    # cannot score green.
    for _ in range(6):
        time.sleep(5)
        instances = _describe_group(ctx, group_name)["Instances"]
        assert instances == [], (
            f"instances were launched despite the Launch process being suspended: {instances}"
        )
        ec2_instances = _ec2_instances_for_group(ctx, group_name)
        assert ec2_instances == [], (
            f"EC2 shows instance(s) from this group's launch template despite Launch being "
            f"suspended (independent of the ASG's own Instances field): {ec2_instances}"
        )

    asg.resume_processes(AutoScalingGroupName=group_name, ScalingProcesses=["Launch"])
    resumed = _describe_group(ctx, group_name)["SuspendedProcesses"]
    assert not any(p["ProcessName"] == "Launch" for p in resumed), (
        f"Launch process still shown as suspended after ResumeProcesses: {resumed}"
    )

    converged = _poll_until(
        lambda: _describe_group(ctx, group_name)["Instances"],
        lambda instances: len(instances) == 2
        and all(i["LifecycleState"] == "InService" for i in instances),
        timeout_s=300,
        interval_s=6,
    )
    assert len(converged) == 2, f"group never converged to DesiredCapacity=2 after ResumeProcesses: {converged}"
    assert all(i["LifecycleState"] == "InService" for i in converged), converged


# ===== helpers =====
def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while time.monotonic() < deadline:
        if predicate(result):
            return result
        time.sleep(interval_s)
        result = probe()
    return result


def _describe_group(ctx, group_name: str) -> dict:
    asg = ctx.client("autoscaling")
    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[group_name])["AutoScalingGroups"]
    assert groups, f"group {group_name} not found"
    return groups[0]


def _default_subnet(ctx) -> dict[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    assert subnets, f"no subnets available in VPC {vpc_id!r}"
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
        images.sort(key=lambda im: im["CreationDate"], reverse=True)
        return images[0]["ImageId"]


_GROUP_TAG_KEY = "sim2real-check-group"


def _create_launch_template(ctx, ami_id: str, tag_value: str, instance_type: str = "t3.micro") -> str:
    ec2 = ctx.client("ec2")
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    tag = {"Key": _GROUP_TAG_KEY, "Value": tag_value}
    resp = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={
            "ImageId": ami_id,
            "InstanceType": instance_type,
            "TagSpecifications": [{"ResourceType": "instance", "Tags": [tag]}],
        },
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [tag]}],
    )
    lt_id = resp["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))
    return lt_id


def _ec2_instances_for_group(ctx, group_name: str) -> list[str]:
    ec2 = ctx.client("ec2")
    reservations = ec2.describe_instances(
        Filters=[
            {"Name": f"tag:{_GROUP_TAG_KEY}", "Values": [group_name]},
            {"Name": "instance-state-name", "Values": ["pending", "running"]},
        ]
    )["Reservations"]
    return sorted(i["InstanceId"] for r in reservations for i in r["Instances"])


def _create_asg(ctx, name: str, lt_id: str, min_size: int, max_size: int, desired: int, subnet_id: str, **kwargs):
    asg = ctx.client("autoscaling")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateId": lt_id},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=subnet_id,
        Tags=[{"Key": _GROUP_TAG_KEY, "Value": name, "PropagateAtLaunch": True}],
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
