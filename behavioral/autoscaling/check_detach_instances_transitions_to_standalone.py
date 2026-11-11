"""detach-instances-transitions-to-standalone."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "detach-instances-transitions-to-standalone"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachInstances folds a standalone EC2 instance into the group's capacity;
    DetachInstances (with the decrement flag) pulls it back out and drops DesiredCapacity."""
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    subnet = _default_subnet(ctx)
    ami_id = _al2023_ami(ctx)

    group_name = ctx.unique_name("sim2real-behav-asg-")
    _create_empty_asg(ctx, group_name, subnet["subnet_id"], max_size=2)

    instance_id = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet["subnet_id"],
        TagSpecifications=[
            {
                "ResourceType": "instance",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-standalone-")}],
            }
        ],
    )["Instances"][0]["InstanceId"]

    def _terminate_standalone():
        try:
            ec2.terminate_instances(InstanceIds=[instance_id])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidInstanceID.NotFound":
                raise

    ctx.on_cleanup(_terminate_standalone)

    ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})

    asg.attach_instances(InstanceIds=[instance_id], AutoScalingGroupName=group_name)

    group_after_attach = _poll_until(
        lambda: _describe_group(ctx, group_name),
        lambda g: g["DesiredCapacity"] == 1
        and any(
            i["InstanceId"] == instance_id and i["LifecycleState"] in ("InService", "Standby", "Pending")
            for i in g["Instances"]
        ),
        timeout_s=120,
        interval_s=4,
    )
    assert group_after_attach["DesiredCapacity"] == 1, (
        f"DesiredCapacity did not increment after AttachInstances: {group_after_attach['DesiredCapacity']}"
    )
    assert any(i["InstanceId"] == instance_id for i in group_after_attach["Instances"]), (
        "attached instance missing from group Instances list"
    )

    # DetachInstances only accepts instances in InService/Standby/Pending:Refresh - wait for the
    # freshly-attached instance to clear the transient Pending state (health-check bootstrap)
    # before attempting to detach it, rather than racing DetachInstances against AttachInstances.
    attached_instance = _poll_until(
        lambda: _find_instance(ctx, group_name, instance_id),
        lambda i: i is not None and i["LifecycleState"] in ("InService", "Standby"),
        timeout_s=180,
        interval_s=5,
    )
    assert attached_instance is not None and attached_instance["LifecycleState"] in ("InService", "Standby"), (
        f"attached instance never settled into InService/Standby before detach: {attached_instance}"
    )

    asg.detach_instances(
        InstanceIds=[instance_id], AutoScalingGroupName=group_name, ShouldDecrementDesiredCapacity=True
    )

    group_after_detach = _poll_until(
        lambda: _describe_group(ctx, group_name),
        lambda g: g["DesiredCapacity"] == 0 and not any(i["InstanceId"] == instance_id for i in g["Instances"]),
        timeout_s=120,
        interval_s=4,
    )
    assert group_after_detach["DesiredCapacity"] == 0, (
        f"DesiredCapacity did not decrement after DetachInstances: {group_after_detach['DesiredCapacity']}"
    )
    assert not any(i["InstanceId"] == instance_id for i in group_after_detach["Instances"]), (
        "detached instance still listed in group Instances"
    )

    # "Transitions to standalone" means the instance survives independently of the group,
    # not that DetachInstances terminated it — confirm via an independent EC2-side read.
    standalone_instance = ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]
    assert standalone_instance["State"]["Name"] in ("running", "pending"), (
        f"detached instance should remain alive as a standalone EC2 instance, "
        f"got state {standalone_instance['State']!r}"
    )


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


def _find_instance(ctx, group_name: str, instance_id: str):
    group = _describe_group(ctx, group_name)
    return next((i for i in group["Instances"] if i["InstanceId"] == instance_id), None)


def _default_subnet(ctx) -> dict[str, str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
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


def _create_empty_asg(ctx, name: str, subnet_id: str, max_size: int = 2) -> str:
    ec2 = ctx.client("ec2")
    asg = ctx.client("autoscaling")
    ami_id = _al2023_ami(ctx)
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    lt_id = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt_id))

    asg.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateId": lt_id},
        MinSize=0,
        MaxSize=max_size,
        DesiredCapacity=0,
        VPCZoneIdentifier=subnet_id,
    )

    def _cleanup():
        """Teardown: force-delete the group; tolerate only its not-found, retry a transient
        refusal (an in-flight scaling activity, resource contention) for 60 s, and raise anything
        else."""
        deadline = time.monotonic() + 60
        while True:
            try:
                asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
                return
            except ClientError as exc:
                error = exc.response.get("Error", {})
                if error.get("Code") == "ValidationError" and "not found" in error.get("Message", ""):
                    return
                if error.get("Code") not in (
                    "ScalingActivityInProgress", "ResourceContention"
                ) or time.monotonic() >= deadline:
                    raise
            time.sleep(2)

    ctx.on_cleanup(_cleanup)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
