"""asg-cooldown-prevents-premature-ec2-termination."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "asg-cooldown-prevents-premature-ec2-termination"
GROUP = "resource-binding"
SERVICES = ["autoscaling", "ec2", "elbv2"]

_PREFIX = "sim2real-asg-"
# See "Scaling cooldowns for Amazon EC2 Auto Scaling":
# https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-scaling-cooldowns.html
# "After your Auto Scaling group launches or terminates instances, it waits for a cooldown
# period to end before any further scaling activities initiated by simple scaling policies
# can start." The cooldown clock starts once the previous activity's instance finishes
# terminating, so we poll for that condition rather than sleeping a fixed duration.
_COOLDOWN_S = 60


# timing:real-time — cooldown: 60 s https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-scaling-cooldowns.html
@tags("axis:rejection", "cap:c4", "concern:negative-classes", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A SimpleScaling policy's cooldown blocks a second ExecutePolicy call, then allows it once cooldown elapses."""
    vpc_id, subnet_id = _default_subnet(ctx)
    sg_id = _create_security_group(ctx, vpc_id)
    ami_id = _latest_al2023_ami(ctx)
    lt_id = _create_launch_template(ctx, ami_id, sg_id)

    name = ctx.unique_name(f"{_PREFIX}cd-")
    # DefaultCooldown=0 isolates this check to the policy's own Cooldown: the initial
    # launch activity (creating the group) must not leave a lingering group-level
    # cooldown that would confound the first ExecutePolicy call below.
    _create_asg(ctx, name, lt_id, subnet_id, min_size=1, max_size=3, desired=3, extra={"DefaultCooldown": 0})
    _wait_for_in_service_count(ctx, name, 3)

    asg = ctx.client("autoscaling")
    policy_name = ctx.unique_name(f"{_PREFIX}policy-")
    asg.put_scaling_policy(
        AutoScalingGroupName=name,
        PolicyName=policy_name,
        PolicyType="SimpleScaling",
        AdjustmentType="ChangeInCapacity",
        ScalingAdjustment=-1,
        Cooldown=_COOLDOWN_S,
    )

    # First execution: no cooldown active yet, so it must actually scale in (3 -> 2).
    _execute_policy_retrying(asg, name, policy_name)
    term_completed_at = _wait_for_desired_and_in_service(ctx, name, 2, timeout_s=420)

    # Second execution, fired immediately after the first activity finished: must be a
    # no-op because the group is still inside its cooldown window. AWS may express that
    # block either as a silent no-op (DesiredCapacity unchanged) or as a ScalingActivityInProgress
    # fault if the prior activity's bookkeeping hasn't fully settled -- both mean the same thing
    # here: the second scale-in did not go through.
    elapsed_before_second_call = time.monotonic() - term_completed_at
    assert elapsed_before_second_call < _COOLDOWN_S, "test setup invariant: first scale-in must finish well inside cooldown window"
    try:
        asg.execute_policy(AutoScalingGroupName=name, PolicyName=policy_name, HonorCooldown=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ScalingActivityInProgress":
            raise

    poll_deadline = min(time.monotonic() + 45, term_completed_at + _COOLDOWN_S - 5)
    while time.monotonic() < poll_deadline:
        group = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0]
        assert group["DesiredCapacity"] == 2, "cooldown must have blocked the second scale-in"
        time.sleep(10)

    # Wait out the remainder of the documented cooldown window, then confirm the policy
    # can scale in again once cooldown has elapsed (the positive control for this check).
    while time.monotonic() < term_completed_at + _COOLDOWN_S + 5:
        time.sleep(5)

    _execute_policy_retrying(asg, name, policy_name)
    _wait_for_desired_and_in_service(ctx, name, 1, timeout_s=420)


def _execute_policy_retrying(asg, name, policy_name, timeout_s=90, interval_s=5):
    """ExecutePolicy can 400 with ScalingActivityInProgressFault if the ASG's internal
    activity bookkeeping for the group's initial launch hasn't settled yet, even though the
    instances are already InService -- that settling lags instance state slightly. Retry past
    that race rather than treat it as the cooldown behavior under test.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            asg.execute_policy(AutoScalingGroupName=name, PolicyName=policy_name, HonorCooldown=True)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ScalingActivityInProgress":
                raise
            last_err = exc
            time.sleep(interval_s)
    raise AssertionError(f"ExecutePolicy never cleared ScalingActivityInProgress within {timeout_s}s: {last_err}")


def _wait_for_desired_and_in_service(ctx, name, count, timeout_s=420, interval_s=15):
    asg = ctx.client("autoscaling")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        group = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"][0]
        in_service = [i for i in group["Instances"] if i["LifecycleState"] == "InService"]
        last = (group["DesiredCapacity"], len(in_service))
        if group["DesiredCapacity"] == count and len(in_service) == count:
            return time.monotonic()
        time.sleep(interval_s)
    raise AssertionError(f"expected DesiredCapacity/InService == {count}, last observed {last}")


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
        TagSpecifications=[{"ResourceType": "security-group", "Tags": _sim2real_tags(name)}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_security_group_when_free(ec2, sg_id))
    return sg_id


def _sim2real_tags(name):
    return [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}]


def _create_launch_template(ctx, ami_id, sg_id, instance_type="t3.micro", extra_tags=None):
    ec2 = ctx.client("ec2")
    name = ctx.unique_name(f"{_PREFIX}lt-")
    tags = _sim2real_tags(name) + (extra_tags or [])
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
        HealthCheckGracePeriod=30,
        Tags=[{"ResourceId": name, "ResourceType": "auto-scaling-group", "Key": k, "Value": v, "PropagateAtLaunch": False} for k, v in {"Name": name, "sim2real": "true"}.items()],
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
        if exc.response["Error"]["Code"] != "ValidationError":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]
        if not groups:
            break
        time.sleep(10)
    if ids:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            resp = ec2.describe_instances(InstanceIds=ids)
            states = {i["State"]["Name"] for r in resp["Reservations"] for i in r["Instances"]}
            if states <= {"terminated"} or not states:
                break
            time.sleep(10)


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
