"""asg-suspended-scheduled-actions-skip-an-occurrence-and-resume-without-backfill."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "asg-suspended-scheduled-actions-skip-an-occurrence-and-resume-without-backfill"
GROUP = "process-suspension"
SERVICES = ["autoscaling"]

_CIDR_OCTET = 226
_PREFIX = "sim2real-behav-"
_MANAGED_TAGS = {"sim2real": CHECK[:200], "sim2real:managed": "true"}
#: The first occurrence is at least this far out, so both groups carry the action before it.
_LEAD_S = 90
#: Minutes between the two occurrences of the one recurring action.
_GAP_MIN = 2
#: Ceiling for one occurrence to come due and execute.
_OCCURRENCE_TIMEOUT_S = 240
#: Ceiling for the groups to drain and disappear after ForceDelete.
_GROUPS_GONE_S = 300
#: Ceiling for one subnet or VPC delete to outlast the ENIs of terminated instances.
_NET_DELETE_S = 50


# timing:real-time — schedule: 120 s
@tags("axis:negative-delivery", "cap:c4", "concern:eventing", "concern:data-plane",
      "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A suspended ScheduledActions process skips an occurrence that a control group executes and
    records the skip; resuming does not back-fill the missed occurrence, and the next occurrence
    then fires.

    Reference: https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-suspend-resume-processes.html
    """
    asg = ctx.client("autoscaling")

    ami = _al2023_ami(ctx)
    subnets = _network(ctx, "t3.micro")
    lt_name = _launch_template(ctx, ami)
    control = _create_asg(ctx, lt_name, subnets)
    subject = _create_asg(ctx, lt_name, subnets)

    # Break exactly one thing, on the subject only.
    asg.suspend_processes(AutoScalingGroupName=subject, ScalingProcesses=["ScheduledActions"])
    suspended = {p["ProcessName"] for p in _group(ctx, subject)["SuspendedProcesses"]}
    assert suspended == {"ScheduledActions"}, (
        f"the subject must have exactly ScheduledActions suspended, got {sorted(suspended)!r}"
    )
    control_suspended = _group(ctx, control)["SuspendedProcesses"]
    assert not control_suspended, (
        f"the control group must have nothing suspended, got {control_suspended!r}"
    )

    # Two occurrences of ONE recurring action, _GAP_MIN minutes apart.
    now = datetime.now(timezone.utc)
    first = (now + timedelta(seconds=_LEAD_S)).replace(second=0, microsecond=0) + timedelta(minutes=1)
    second = first + timedelta(minutes=_GAP_MIN)
    recurrence = f"{first.minute},{second.minute} * * * *"
    action = ctx.unique_name("sim2real-behav-as-sched-")
    for name in (control, subject):
        asg.put_scheduled_update_group_action(
            AutoScalingGroupName=name, ScheduledActionName=action,
            Recurrence=recurrence, DesiredCapacity=1,
        )
    for name in (control, subject):
        listed = _actions(ctx, name)
        assert [a["ScheduledActionName"] for a in listed] == [action], (
            f"{name} must carry exactly the one scheduled action {action!r}, got {listed!r}"
        )
        assert listed[0]["Recurrence"] == recurrence, (
            f"{name}'s action recurrence was stored as {listed[0]['Recurrence']!r}, "
            f"expected {recurrence!r}"
        )
        assert _group(ctx, name)["DesiredCapacity"] == 0, (
            f"{name} moved before any occurrence was due: {_group(ctx, name)['DesiredCapacity']!r}"
        )

    # The barrier: the control's scheduler fires at the first occurrence.
    _poll(
        lambda: _group(ctx, control)["DesiredCapacity"], lambda d: d == 1,
        timeout_s=_until(first) + _OCCURRENCE_TIMEOUT_S, interval_s=5,
        description=f"the control's scheduled action fired at {first.isoformat()}",
    )
    fired_at = datetime.now(timezone.utc)
    assert fired_at >= first, (
        f"the control moved at {fired_at.isoformat()}, BEFORE the occurrence {first.isoformat()}"
    )
    control_ran = [a for a in _activities(ctx, control)
                   if a["Description"] == f"Executing scheduled action {action}"]
    assert len(control_ran) == 1, (
        f"the control's activity history must record exactly one execution of {action!r}, got "
        f"{[a['Description'] for a in _activities(ctx, control)]!r}"
    )
    subject_desired = _group(ctx, subject)["DesiredCapacity"]
    assert subject_desired == 0, (
        f"the group with ScheduledActions suspended moved anyway at the first occurrence: "
        f"DesiredCapacity={subject_desired!r}, expected 0"
    )

    # Sustained absence: the subject stays put for 30 more seconds after the barrier.
    hold_until = time.monotonic() + 30
    samples = 0
    while True:
        d = _group(ctx, subject)["DesiredCapacity"]
        assert d == 0, (
            f"the suspended subject's DesiredCapacity moved to {d!r} after the first occurrence"
        )
        samples += 1
        if time.monotonic() >= hold_until:
            break
        time.sleep(5)
    assert samples >= 3, f"the absence must be sampled at least 3 times, got {samples}"
    # The scheduler SAW the occurrence and recorded the skip; it did not merely miss it.
    subject_activities = [a["Description"] for a in _activities(ctx, subject)]
    assert subject_activities == [
        f"Skipping scheduled action {action} since scheduled actions are suspended for the group."
    ], (
        f"the suspended subject's activity history must record exactly one skip of {action!r} "
        f"and no execution, got {subject_activities!r}"
    )
    subject_listed = [a["ScheduledActionName"] for a in _actions(ctx, subject)]
    assert subject_listed == [action], (
        f"the skipped recurring action must still be scheduled on the subject, got "
        f"{subject_listed!r}"
    )

    # Repair the one broken thing, with enough margin before the second occurrence.
    margin = _until(second)
    assert margin >= 30, (
        f"too little time left before the second occurrence to observe the resume: {margin:.0f}s"
    )
    asg.resume_processes(AutoScalingGroupName=subject, ScalingProcesses=["ScheduledActions"])
    remaining = _group(ctx, subject)["SuspendedProcesses"]
    assert not remaining, f"after the resume nothing may stay suspended, got {remaining!r}"

    # Resuming does NOT back-fill the missed occurrence: the subject stays at 0 up to the next.
    samples = 0
    while _until(second) > 10:
        d = _group(ctx, subject)["DesiredCapacity"]
        assert d == 0, (
            f"resuming ScheduledActions back-filled the skipped occurrence: DesiredCapacity={d!r} "
            f"{_until(second):.0f}s before the next occurrence {second.isoformat()}"
        )
        samples += 1
        time.sleep(5)
    assert samples >= 3, f"the post-resume absence must be sampled at least 3 times, got {samples}"

    # The NEXT occurrence of the same action fires on the resumed group.
    _poll(
        lambda: _group(ctx, subject)["DesiredCapacity"], lambda d: d == 1,
        timeout_s=_until(second) + _OCCURRENCE_TIMEOUT_S, interval_s=5,
        description=f"the resumed subject's next occurrence fired at {second.isoformat()}",
    )
    moved_at = datetime.now(timezone.utc)
    assert moved_at >= second, (
        f"the subject moved at {moved_at.isoformat()}, before the next occurrence "
        f"{second.isoformat()}"
    )
    subject_activities = [a["Description"] for a in _activities(ctx, subject)]
    executed = [d for d in subject_activities if d == f"Executing scheduled action {action}"]
    assert len(executed) == 1, (
        f"the resumed subject must record exactly one execution of {action!r}, got "
        f"{subject_activities!r}"
    )

    # Drain in the body: the groups' instances outlive the cleanup bound, and the network under
    # them cannot go until they do.
    for name in (control, subject):
        _force_delete_group(ctx, name)
    _poll(lambda: [n for n in (control, subject) if _describe_groups(ctx, n)], lambda left: not left,
          timeout_s=_GROUPS_GONE_S, interval_s=5,
          description="both groups gone after ForceDelete")


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


def _code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def _force_delete_group(ctx, name: str) -> None:
    """ForceDelete a group; a group already gone or already being deleted is done."""
    groups = _describe_groups(ctx, name)
    if not groups or groups[0].get("Status") == "Delete in progress":
        return
    try:
        ctx.client("autoscaling").delete_auto_scaling_group(
            AutoScalingGroupName=name, ForceDelete=True)
    except ClientError as exc:
        message = exc.response.get("Error", {}).get("Message", "")
        if _code(exc) == "ValidationError" and "not found" in message.lower():
            return
        raise


def _delete_net(ctx, op: str, gone_code: str, **ident) -> None:
    """Delete a subnet or VPC, retrying DependencyViolation for a bounded time; raises otherwise."""
    ec2 = ctx.client("ec2")
    deadline = time.monotonic() + _NET_DELETE_S
    while True:
        try:
            getattr(ec2, op)(**ident)
            return
        except ClientError as exc:
            if _code(exc) == gone_code:
                return
            if _code(exc) != "DependencyViolation" or time.monotonic() >= deadline:
                raise
        time.sleep(5)


def _delete_launch_template(ctx, name: str) -> None:
    try:
        ctx.client("ec2").delete_launch_template(LaunchTemplateName=name)
    except ClientError as exc:
        if _code(exc) != "InvalidLaunchTemplateName.NotFoundException":
            raise


def _poll(fn, pred, *, timeout_s, interval_s=10, description="condition"):
    """Poll fn() until pred() holds; RAISE with the last observed value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = fn()
    while not pred(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s:.0f}s; last={last!r}")
        time.sleep(interval_s)
        last = fn()
    return last


def _al2023_ami(ctx) -> str:
    param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    value = ctx.client("ssm").get_parameter(Name=param)["Parameter"]["Value"]
    assert value.startswith("ami-"), f"{param} did not resolve to an AMI: {value!r}"
    return value


def _network(ctx, instance_type: str) -> list[str]:
    """A dedicated VPC with one subnet in an AZ that really offers instance_type."""
    ec2 = ctx.client("ec2")
    offered = sorted(
        o["Location"]
        for o in ec2.describe_instance_type_offerings(
            LocationType="availability-zone",
            Filters=[{"Name": "instance-type", "Values": [instance_type]}],
        )["InstanceTypeOfferings"]
    )
    available = {
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    }
    azs = [z for z in offered if z in available][:1]
    assert azs, f"no available AZ offers {instance_type!r} in {ctx.region} (offered={offered!r})"
    vpc_id = ec2.create_vpc(
        CidrBlock=f"10.{_CIDR_OCTET}.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": _tags_kv()}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ctx, "delete_vpc", "InvalidVpcID.NotFound", VpcId=vpc_id))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=f"10.{_CIDR_OCTET}.0.0/24", AvailabilityZone=azs[0],
        TagSpecifications=[{"ResourceType": "subnet", "Tags": _tags_kv()}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ctx, "delete_subnet", "InvalidSubnetID.NotFound",
                                       SubnetId=subnet_id))
    return [subnet_id]


def _launch_template(ctx, ami: str, *, instance_type: str = "t3.micro") -> str:
    """Tag BOTH the instance and its volume AT LAUNCH, so the ids an ASG creates stay
    attributable to this check."""
    name = ctx.unique_name(f"{_PREFIX}as-lt-")
    ctx.client("ec2").create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "ImageId": ami,
            "InstanceType": instance_type,
            "TagSpecifications": [
                {"ResourceType": "instance", "Tags": _tags_kv()},
                {"ResourceType": "volume", "Tags": _tags_kv()},
            ],
        },
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _tags_kv()}],
    )
    ctx.on_cleanup(lambda: _delete_launch_template(ctx, name))
    return name


def _create_asg(ctx, lt_name: str, subnets) -> str:
    name = ctx.unique_name(f"{_PREFIX}as-grp-")
    ctx.client("autoscaling").create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0, MaxSize=1, DesiredCapacity=0,
        VPCZoneIdentifier=",".join(subnets),
        HealthCheckGracePeriod=0, DefaultCooldown=0,
        Tags=[{"Key": k, "Value": v, "PropagateAtLaunch": True} for k, v in _MANAGED_TAGS.items()],
    )
    ctx.on_cleanup(lambda: _force_delete_group(ctx, name))
    return name


def _describe_groups(ctx, name: str) -> list:
    groups = []
    for page in ctx.client("autoscaling").get_paginator(
        "describe_auto_scaling_groups"
    ).paginate(AutoScalingGroupNames=[name]):
        groups += page["AutoScalingGroups"]
    return groups


def _group(ctx, name: str) -> dict:
    groups = _describe_groups(ctx, name)
    assert groups, f"auto scaling group {name!r} not found"
    return groups[0]


def _activities(ctx, name: str) -> list:
    out = []
    for page in ctx.client("autoscaling").get_paginator(
        "describe_scaling_activities"
    ).paginate(AutoScalingGroupName=name):
        out += page["Activities"]
    return out


def _until(when: datetime) -> float:
    return (when - datetime.now(timezone.utc)).total_seconds()


def _actions(ctx, name: str) -> list:
    out = []
    for page in ctx.client("autoscaling").get_paginator(
        "describe_scheduled_actions"
    ).paginate(AutoScalingGroupName=name):
        out += page["ScheduledUpdateGroupActions"]
    return out


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
