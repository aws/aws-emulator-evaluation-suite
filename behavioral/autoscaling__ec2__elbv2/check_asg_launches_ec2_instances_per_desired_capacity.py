"""asg-launches-ec2-instances-per-desired-capacity."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "asg-launches-ec2-instances-per-desired-capacity"
GROUP = "resource-binding"
SERVICES = ["autoscaling", "ec2", "elbv2"]

_PREFIX = "sim2real-asg-"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An Auto Scaling group launches exactly DesiredCapacity real EC2 instances, running."""
    vpc_id, subnet_id = _default_subnet(ctx)
    sg_id = _create_security_group(ctx, vpc_id)
    ami_id = _latest_al2023_ami(ctx)
    lt_id = _create_launch_template(ctx, ami_id, sg_id)

    name = ctx.unique_name(f"{_PREFIX}dc-")
    _create_asg(ctx, name, lt_id, subnet_id, min_size=1, max_size=3, desired=2)

    ids = _wait_for_in_service_count(ctx, name, 2)
    assert len(ids) == 2, f"expected 2 InService instance ids, got {ids}"

    ec2 = ctx.client("ec2")
    resp = ec2.describe_instances(InstanceIds=ids)
    instances = [i for r in resp["Reservations"] for i in r["Instances"]]
    assert len(instances) == 2, f"expected ec2:DescribeInstances to return 2 instances for {ids}, got {len(instances)}"
    running = [i for i in instances if i["State"]["Name"] == "running"]
    assert len(running) == 2, f"expected 2 running instances, got states {[i['State']['Name'] for i in instances]}"

    # Cross-check binding: each launched instance is tagged back to this exact ASG.
    for inst in instances:
        tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
        assert tags.get("aws:autoscaling:groupName") == name, (
            f"expected instance {inst['InstanceId']} tagged aws:autoscaling:groupName={name}, "
            f"got {tags.get('aws:autoscaling:groupName')!r}"
        )

    group = ctx.client("autoscaling").describe_auto_scaling_groups(AutoScalingGroupNames=[name])[
        "AutoScalingGroups"
    ][0]
    assert group["DesiredCapacity"] == 2, f"expected DesiredCapacity == 2, got {group['DesiredCapacity']}"
    assert len(group["Instances"]) == 2, f"expected 2 instances in the ASG's own record, got {len(group['Instances'])}"


def _default_subnet(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC in this account/region; use the run's shared network (or wire a "
            "dedicated test VPC/subnet) to close this gap"
        )
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no network subnets; create one to close this gap")
    return vpc_id, subnets[0]["SubnetId"]


def _latest_al2023_ami(ctx):
    ec2 = ctx.client("ec2")
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]},
        ],
    )["Images"]
    if not images:
        raise AssertionError("no Amazon Linux 2023 AMI visible to this account/region to launch test instances")
    images.sort(key=lambda i: i["CreationDate"], reverse=True)
    return images[0]["ImageId"]


def _create_security_group(ctx, vpc_id):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(f"{_PREFIX}sg-")
    sg_id = ec2.create_security_group(
        GroupName=name, Description="sim2real behavioral test sg", VpcId=vpc_id
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))
    return sg_id


def _create_launch_template(ctx, ami_id, sg_id, instance_type="t3.micro", extra_tags=None):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(f"{_PREFIX}lt-")
    tags = [{"Key": "Name", "Value": name}] + (extra_tags or [])
    lt = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "ImageId": ami_id,
            "InstanceType": instance_type,
            "SecurityGroupIds": [sg_id],
            "TagSpecifications": [{"ResourceType": "instance", "Tags": tags}],
        },
    )["LaunchTemplate"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt["LaunchTemplateId"]))
    return lt["LaunchTemplateId"]


def _create_asg(ctx, name, lt_id, subnet_id, min_size, max_size, desired, lt_version="$Latest", extra=None):
    asg = ctx.client("autoscaling")
    kwargs = dict(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateId": lt_id, "Version": lt_version},
        MinSize=min_size,
        MaxSize=max_size,
        DesiredCapacity=desired,
        VPCZoneIdentifier=subnet_id,
        HealthCheckGracePeriod=60,
    )
    if extra:
        kwargs.update(extra)
    asg.create_auto_scaling_group(**kwargs)
    ctx.on_cleanup(lambda: _terminate_asg_and_wait(ctx, name))
    return name


def _terminate_asg_and_wait(ctx, name, timeout_s=420):
    """Force-delete the group, then wait until it and its instances are gone: a refusal while a
    scaling activity runs is retried every 2 s, a group already gone is done, anything else raises."""
    from botocore.exceptions import ClientError

    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ids = _group_instance_ids(ctx, name)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
            break
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
                break
            busy = ("ScalingActivityInProgress", "ResourceInUse", "ResourceContention")
            if err["Code"] not in busy or time.monotonic() >= deadline:
                raise
        time.sleep(2)
    while asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]:
        if time.monotonic() >= deadline:
            raise TimeoutError(f"auto scaling group {name} still listed at the teardown deadline")
        time.sleep(2)
    if ids:
        deadline = time.monotonic() + timeout_s
        while True:
            resp = ec2.describe_instances(InstanceIds=ids)
            states = {i["State"]["Name"] for r in resp["Reservations"] for i in r["Instances"]}
            if states <= {"terminated"}:
                break
            if time.monotonic() >= deadline:
                raise TimeoutError(f"instances {ids} of {name} not terminated: {states}")
            time.sleep(2)


def _group_instance_ids(ctx, name, lifecycle_states=None):
    asg = ctx.client("autoscaling")
    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]
    if not groups:
        return []
    instances = groups[0]["Instances"]
    if lifecycle_states:
        instances = [i for i in instances if i["LifecycleState"] in lifecycle_states]
    return [i["InstanceId"] for i in instances]


def _wait_for_in_service_count(ctx, name, count, timeout_s=600, interval_s=15):
    deadline = time.monotonic() + timeout_s
    last = -1
    while time.monotonic() < deadline:
        ids = _group_instance_ids(ctx, name, lifecycle_states=("InService",))
        last = len(ids)
        if last == count:
            return ids
        time.sleep(interval_s)
    raise AssertionError(f"expected {count} InService instances, saw {last} after {timeout_s}s")



def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=15.0):
    """Delete a security group once the ENIs still holding it are released (DependencyViolation)."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_security_group(GroupId=sg_id)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "InvalidGroup.NotFound":
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
