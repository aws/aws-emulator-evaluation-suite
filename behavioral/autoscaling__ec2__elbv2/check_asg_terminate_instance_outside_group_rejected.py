"""asg-terminate-instance-outside-group-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "asg-terminate-instance-outside-group-rejected"
GROUP = "permission-boundary"
SERVICES = ["autoscaling", "ec2", "elbv2"]

_PREFIX = "sim2real-asg-"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TerminateInstanceInAutoScalingGroup is rejected for an EC2 instance outside any ASG, but works for one inside it."""
    vpc_id, subnet_id = _default_subnet(ctx)
    sg_id = _create_security_group(ctx, vpc_id)
    ami_id = _latest_al2023_ami(ctx)
    lt_id = _create_launch_template(ctx, ami_id, sg_id)

    name = ctx.unique_name(f"{_PREFIX}outside-")
    # MinSize=0 so the positive-control terminate-with-decrement below (1 -> 0) is not itself
    # rejected by AWS's "desiredSize equals minSize" guard -- that guard is orthogonal to the
    # membership check this test isolates.
    _create_asg(ctx, name, lt_id, subnet_id, min_size=0, max_size=1, desired=1)
    member_ids = _wait_for_in_service_count(ctx, name, 1)
    member_id = member_ids[0]

    ec2 = ctx.client("ec2")
    outsider_id = _run_standalone_instance(ctx, ami_id, sg_id, subnet_id)

    asg = ctx.client("autoscaling")
    code, message = _error(
        lambda: asg.terminate_instance_in_auto_scaling_group(
            InstanceId=outsider_id, ShouldDecrementDesiredCapacity=False
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    expected_message = f"Instance Id not found - No managed instance found for instance ID: {outsider_id}"
    assert message == expected_message, f"message {message!r}, expected {expected_message!r}"

    # Effect absent: the instance that isn't in any ASG must still be running.
    state = ec2.describe_instances(InstanceIds=[outsider_id])["Reservations"][0]["Instances"][0]["State"]["Name"]
    assert state == "running", f"outsider instance should be untouched, got state {state!r}"

    # Positive control: the exact same call succeeds for the instance that IS in the group.
    asg.terminate_instance_in_auto_scaling_group(InstanceId=member_id, ShouldDecrementDesiredCapacity=True)

    deadline = time.monotonic() + _budget_s(ctx, 300)
    member_state = None
    while time.monotonic() < deadline:
        member_state = ec2.describe_instances(InstanceIds=[member_id])["Reservations"][0]["Instances"][0]["State"][
            "Name"
        ]
        if member_state == "terminated":
            break
        time.sleep(2)
    if member_state != "terminated" and _budget_spent(ctx):
        raise TimeoutError(f"in-group instance {member_id} terminating: the run budget ended "
                           "first; not graded")
    assert member_state == "terminated", f"in-group instance should have terminated, got {member_state!r}"

    group = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0]
    assert group["DesiredCapacity"] == 0, f"expected DesiredCapacity 0 after decrementing terminate, got {group['DesiredCapacity']!r}"


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _run_standalone_instance(ctx, ami_id, sg_id, subnet_id):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(f"{_PREFIX}outsider-")
    resp = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        MinCount=1,
        MaxCount=1,
        SubnetId=subnet_id,
        SecurityGroupIds=[sg_id],
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    instance_id = resp["Instances"][0]["InstanceId"]

    def _cleanup():
        # Polled by hand: the instance_terminated waiter fails outright on a 'pending' read, which
        # an instance terminated right after launch can still return. Gone (NotFound) counts as done.
        try:
            ec2.terminate_instances(InstanceIds=[instance_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                raise
            return
        deadline = time.monotonic() + 600
        last = None
        while time.monotonic() < deadline:
            try:
                last = _instance_state(ec2, instance_id)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                    raise
                return
            if last == "terminated":
                return
            time.sleep(2)
        raise RuntimeError(f"standalone instance {instance_id} not terminated after 600s, last state {last!r}")

    ctx.on_cleanup(_cleanup)
    deadline = time.monotonic() + _budget_s(ctx, 600)
    state = None
    while time.monotonic() < deadline:
        # A just-launched instance can be briefly unknown to DescribeInstances.
        try:
            state = _instance_state(ec2, instance_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                raise
            state = None
        if state == "running":
            return instance_id
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"standalone instance {instance_id} reaching running: the run budget "
                           "ended first; not graded")
    raise AssertionError(f"standalone instance {instance_id} did not reach running, last state {state!r}")


def _instance_state(ec2, instance_id):
    return ec2.describe_instances(InstanceIds=[instance_id])["Reservations"][0]["Instances"][0]["State"]["Name"]


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
    tags_ = [{"Key": "Name", "Value": name}] + (extra_tags or [])
    lt = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "ImageId": ami_id,
            "InstanceType": instance_type,
            "SecurityGroupIds": [sg_id],
            "TagSpecifications": [{"ResourceType": "instance", "Tags": tags_}],
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
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ids = _group_instance_ids(ctx, name)
    try:
        asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    except ClientError as exc:
        if "not found" not in exc.response["Error"].get("Message", "").lower():
            raise
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]
        if not groups:
            break
        last = groups[0].get("Status")
        time.sleep(2)
    else:
        raise RuntimeError(f"auto scaling group {name} was not deleted: {last!r}")
    if ids:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            try:
                resp = ec2.describe_instances(InstanceIds=ids)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "InvalidInstanceID.NotFound":
                    raise
                return
            states = {i["State"]["Name"] for r in resp["Reservations"] for i in r["Instances"]}
            if states <= {"terminated"} or not states:
                return
            last = states
            time.sleep(2)
        raise RuntimeError(f"auto scaling group {name} instances were not terminated: {last!r}")


def _group_instance_ids(ctx, name, lifecycle_states=None):
    asg = ctx.client("autoscaling")
    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]
    if not groups:
        return []
    instances = groups[0]["Instances"]
    if lifecycle_states:
        instances = [i for i in instances if i["LifecycleState"] in lifecycle_states]
    return [i["InstanceId"] for i in instances]


def _wait_for_in_service_count(ctx, name, count, timeout_s=600, interval_s=2):
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = -1
    while time.monotonic() < deadline:
        ids = _group_instance_ids(ctx, name, lifecycle_states=("InService",))
        last = len(ids)
        if last == count:
            return ids
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"{count} InService instances in {name}: the run budget ended first; "
                           "not graded")
    raise AssertionError(f"expected {count} InService instances, saw {last} after {timeout_s}s")



def _delete_security_group_when_free(ec2, sg_id, timeout_s=900.0, interval_s=2.0):
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
