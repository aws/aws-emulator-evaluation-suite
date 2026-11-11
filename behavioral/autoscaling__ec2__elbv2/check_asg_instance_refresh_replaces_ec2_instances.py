"""asg-instance-refresh-replaces-ec2-instances."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "asg-instance-refresh-replaces-ec2-instances"
GROUP = "resource-binding"
SERVICES = ["autoscaling", "ec2", "elbv2"]

_PREFIX = "sim2real-asg-"


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """StartInstanceRefresh rolls every instance over to the new launch template version."""
    vpc_id, subnet_id = _default_subnet(ctx)
    sg_id = _create_security_group(ctx, vpc_id)
    ami_id = _latest_al2023_ami(ctx)
    lt_id = _create_launch_template(ctx, ami_id, sg_id, instance_type="t3.micro")

    # One instance keeps the check short. MaxSize=2 lets the refresh surge (launch the replacement
    # before terminating the original) instead of terminating first -- surging is the faster
    # path since the new instance's boot overlaps the old instance's drain instead of following it.
    name = ctx.unique_name(f"{_PREFIX}refresh-")
    _create_asg(ctx, name, lt_id, subnet_id, min_size=1, max_size=2, desired=1, lt_version="1")

    old_ids = set(_wait_for_in_service_count(ctx, name, 1, timeout_s=70, interval_s=7))
    assert len(old_ids) == 1, f"expected 1 InService instance before the refresh, got {old_ids!r}"

    ec2 = ctx.client("ec2")
    ec2.create_launch_template_version(
        LaunchTemplateId=lt_id,
        SourceVersion="1",
        LaunchTemplateData={"InstanceType": "t3.small"},
    )
    asg = ctx.client("autoscaling")
    asg.update_auto_scaling_group(
        AutoScalingGroupName=name, LaunchTemplate={"LaunchTemplateId": lt_id, "Version": "2"}
    )

    # MinHealthyPercentage=100/MaxHealthyPercentage=200 allows a one-instance surge (up to
    # MaxSize=2): the replacement launches immediately, in parallel with the original still
    # serving, instead of waiting for a terminate to free capacity first.
    refresh_id = asg.start_instance_refresh(
        AutoScalingGroupName=name,
        Preferences={"MinHealthyPercentage": 100, "MaxHealthyPercentage": 200, "InstanceWarmup": 0},
    )["InstanceRefreshId"]

    deadline = time.monotonic() + 180
    status = None
    while time.monotonic() < deadline:
        refreshes = asg.describe_instance_refreshes(
            AutoScalingGroupName=name, InstanceRefreshIds=[refresh_id]
        )["InstanceRefreshes"]
        status = refreshes[0]["Status"]
        if status in ("Successful", "Failed", "Cancelled"):
            break
        time.sleep(2)
    assert status == "Successful", f"instance refresh ended in status {status!r}"

    new_ids = set(_group_instance_ids(ctx, name, lifecycle_states=("InService",)))
    assert len(new_ids) == 1, f"expected 1 InService instance after the refresh, got {new_ids!r}"
    assert new_ids.isdisjoint(old_ids), "instance refresh must replace every original instance"

    resp = ec2.describe_instances(InstanceIds=list(new_ids))
    for inst in (i for r in resp["Reservations"] for i in r["Instances"]):
        assert inst["InstanceType"] == "t3.small", "replacement instance must use the new launch template version"

    resp = ec2.describe_instances(InstanceIds=list(old_ids))
    for inst in (i for r in resp["Reservations"] for i in r["Instances"]):
        assert inst["State"]["Name"] == "terminated", "original instance must have been terminated by the refresh"


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
        GroupName=name,
        Description="sim2real behavioral test sg",
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "security-group", "Tags": [{"Key": "Name", "Value": name}]}
        ],
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
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": tags}],
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
        Tags=[{"Key": "Name", "Value": name, "PropagateAtLaunch": True}],
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
