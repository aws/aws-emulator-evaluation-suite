"""xsvc-autoscaling-2-ec2-terminated-member-is-replaced-at-unchanged-desired-unless-replace-unhealthy-is-suspended."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = (
    "xsvc-autoscaling-2-ec2-terminated-member-is-replaced-at-unchanged-desired-unless-replace-unhealthy-is-suspended"
)
GROUP = "capacity-management"
SERVICES = ["autoscaling", "ec2"]

_INSTANCE_TYPE = "t3.micro"
_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_VPC_CIDR = "10.142.0.0/16"
_SUBNET_CIDR = "10.142.1.0/24"
_TERMINATED_CAUSE = "in response to an EC2 health check indicating it has been terminated or stopped"
_REPLACE_CAUSE = "in response to an unhealthy instance needing to be replaced"


@tags("axis:negative-delivery", "cap:c4", "concern:e2e", "concern:data-plane", "dp:api",
      "plane:data")
def run(ctx) -> None:
    """A group member killed by ec2.TerminateInstances is marked Unhealthy and replaced at unchanged
    DesiredCapacity; a twin with ReplaceUnhealthy suspended launches nothing until it is resumed,
    and ForceDelete then removes both groups and terminates their instances.

    Reference: https://docs.aws.amazon.com/autoscaling/ec2/userguide/as-suspend-resume-processes.html
    """
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-xsvc-asterm-")

    subnet = _network(ctx, ec2, name)
    ami = _ami(ctx)
    ctx.on_cleanup(lambda: _terminate_tagged_instances(ec2, name, wait=False))
    lt = ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "ImageId": ami, "InstanceType": _INSTANCE_TYPE,
            "TagSpecifications": [
                {"ResourceType": "instance",
                 "Tags": _tags_for(name) + [{"Key": "sim2real-asg", "Value": name}]},
                {"ResourceType": "volume", "Tags": _tags_for(name)}]},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": _tags_for(name)}],
    )["LaunchTemplate"]["LaunchTemplateId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: ec2.delete_launch_template(LaunchTemplateId=lt)))

    control = _create_group(ctx, asg, f"{name}-ctl", lt, subnet)
    subject = _create_group(ctx, asg, f"{name}-sub", lt, subnet)

    control_before = _single_in_service(ctx, asg, control, what="setup: control group InService")
    subject_before = _single_in_service(ctx, asg, subject, what="setup: subject group InService")
    assert control_before != subject_before, f"the twins share an instance: {control_before!r}"

    # Break exactly one thing, on the subject only.
    asg.suspend_processes(AutoScalingGroupName=subject, ScalingProcesses=["ReplaceUnhealthy"])
    ctx.on_cleanup(lambda: _resume_all(asg, subject))
    suspended = {p["ProcessName"] for p in _group(asg, subject)["SuspendedProcesses"]}
    assert suspended == {"ReplaceUnhealthy"}, f"subject suspended set is {sorted(suspended)!r}"
    assert _group(asg, control)["SuspendedProcesses"] == [], (
        f"the control group must have nothing suspended: "
        f"{_group(asg, control)['SuspendedProcesses']!r}"
    )

    # The out-of-band act: one EC2 call kills both members in the same instant.
    resp = ec2.terminate_instances(InstanceIds=[control_before, subject_before])
    assert {i["InstanceId"] for i in resp["TerminatingInstances"]} == {control_before,
                                                                      subject_before}, (
        f"TerminateInstances did not acknowledge both members: {resp['TerminatingInstances']!r}"
    )
    for iid in (control_before, subject_before):
        _poll(lambda i=iid: _ec2_state(ec2, i), lambda s: s == "terminated",
              timeout_s=_budget_s(ctx, 300.0), interval_s=1.0, ctx=ctx,
              what=f"EC2 reporting {iid} terminated")

    # The control: replaced, at unchanged desired capacity.
    control_after = _poll(
        lambda: _members(asg, control),
        lambda ms: len(ms) == 1 and ms[0][0] != control_before and ms[0][1] == "InService",
        timeout_s=_budget_s(ctx, 900.0), interval_s=1.0, ctx=ctx,
        what=f"the control group replacing its EC2-terminated instance {control_before}")[0][0]
    group = _group(asg, control)
    assert (group["MinSize"], group["DesiredCapacity"], group["MaxSize"]) == (0, 1, 2), (
        f"replacement must leave the control's capacity at (0, 1, 2): "
        f"{(group['MinSize'], group['DesiredCapacity'], group['MaxSize'])!r}"
    )
    assert _ec2_state(ec2, control_after) == "running", (
        f"the control's replacement {control_after} is not running in EC2"
    )
    acts = _activities(asg, control)
    terminating = [a for a in acts if a["Description"] == f"Terminating EC2 instance: {control_before}"]
    assert len(terminating) == 1 and _TERMINATED_CAUSE in terminating[0]["Cause"], (
        f"the control must record ONE health-check termination of {control_before} whose cause "
        f"names the EC2 health check: {[(a['Description'], a['Cause']) for a in acts]!r}"
    )
    launching = [a for a in acts if a["Description"] == f"Launching a new EC2 instance: {control_after}"]
    assert len(launching) == 1 and _REPLACE_CAUSE in launching[0]["Cause"], (
        f"the control must record ONE replacement launch of {control_after} caused by the "
        f"unhealthy instance: {[(a['Description'], a['Cause']) for a in acts]!r}"
    )

    # The control's completed replacement is the barrier: the suspended subject must have noticed
    # (it stays listed InService/Unhealthy) and done nothing.
    _poll(lambda: _members(asg, subject),
          lambda ms: ms == [(subject_before, "InService", "Unhealthy")],
          timeout_s=_budget_s(ctx, 300.0), interval_s=1.0, ctx=ctx,
          what=f"the suspended subject listing only {subject_before} as InService/Unhealthy "
               f"(no replacement) after the control was replaced")
    group = _group(asg, subject)
    assert group["DesiredCapacity"] == 1, (
        f"the subject's desired capacity moved while suspended: {group['DesiredCapacity']!r}"
    )
    sub_acts = _activities(asg, subject)
    assert [a["Description"] for a in sub_acts] == [
        f"Launching a new EC2 instance: {subject_before}"], (
        f"the suspended subject must have recorded no activity beyond its initial launch: "
        f"{[(a['Description'], a['Cause']) for a in sub_acts]!r}"
    )

    # Repair the one broken thing: the withheld replacement must now happen.
    asg.resume_processes(AutoScalingGroupName=subject, ScalingProcesses=["ReplaceUnhealthy"])
    subject_after = _poll(
        lambda: _members(asg, subject),
        lambda ms: len(ms) == 1 and ms[0][0] != subject_before and ms[0][1] == "InService",
        timeout_s=_budget_s(ctx, 900.0), interval_s=1.0, ctx=ctx,
        what=f"resuming ReplaceUnhealthy replacing {subject_before}")[0][0]
    group = _group(asg, subject)
    assert group["DesiredCapacity"] == 1 and group["SuspendedProcesses"] == [], (
        f"after resume the subject must be at desired 1 with nothing suspended: "
        f"{(group['DesiredCapacity'], group['SuspendedProcesses'])!r}"
    )
    sub_acts = _activities(asg, subject)
    terminating = [a for a in sub_acts
                   if a["Description"] == f"Terminating EC2 instance: {subject_before}"]
    launching = [a for a in sub_acts
                 if a["Description"] == f"Launching a new EC2 instance: {subject_after}"]
    assert len(terminating) == 1 and _TERMINATED_CAUSE in terminating[0]["Cause"], (
        f"the resumed subject must record the health-check termination of {subject_before}: "
        f"{[(a['Description'], a['Cause']) for a in sub_acts]!r}"
    )
    assert len(launching) == 1 and _REPLACE_CAUSE in launching[0]["Cause"], (
        f"the resumed subject must record the replacement launch of {subject_after}: "
        f"{[(a['Description'], a['Cause']) for a in sub_acts]!r}"
    )

    # --- graded teardown leg, in the body because the deletion itself is asserted;
    #     both deletes are issued first, so the wait is the max, not the sum ---
    for group_name in (subject, control):
        _delete_when_idle(ctx, asg, group_name)
    for group_name in (subject, control):
        _poll(lambda g=group_name: _group_or_none(asg, g), lambda g: g is None,
              timeout_s=_budget_s(ctx, 900.0), interval_s=1.0, ctx=ctx,
              what=f"group {group_name} disappearing after ForceDelete")
    alive = _terminate_tagged_instances(ec2, name, wait=True, act=False,
                                        timeout_s=_budget_s(ctx, 600.0))
    if alive and _budget_spent(ctx):
        raise TimeoutError(f"EC2 terminating the instances of {name}: the run budget ended first; "
                           "not graded")
    assert alive == [], f"ForceDelete left instances of {name} not terminated: {alive!r}"
    for iid in (control_after, subject_after):
        assert _ec2_state(ec2, iid) in ("terminated", "__gone__"), (
            f"ForceDelete must terminate the group's instance {iid}: {_ec2_state(ec2, iid)!r}"
        )


def _create_group(ctx, asg, name, lt, subnet):
    asg.create_auto_scaling_group(
        AutoScalingGroupName=name, MinSize=0, MaxSize=2, DesiredCapacity=1,
        HealthCheckType="EC2", HealthCheckGracePeriod=0,
        LaunchTemplate={"LaunchTemplateId": lt, "Version": "$Latest"},
        VPCZoneIdentifier=subnet,
        Tags=[{"Key": "sim2real", "Value": "1", "PropagateAtLaunch": True}])
    ctx.on_cleanup(lambda: _delete_group(asg, name))
    return name


def _single_in_service(ctx, asg, name, *, what):
    ms = _poll(lambda: _members(asg, name),
               lambda xs: len(xs) == 1 and xs[0][1] == "InService" and xs[0][2] == "Healthy",
               timeout_s=_budget_s(ctx, 900.0), interval_s=1.0, what=what,
               ctx=ctx)
    return ms[0][0]


def _members(asg, name):
    return sorted((i["InstanceId"], i["LifecycleState"], i["HealthStatus"])
                  for i in _group(asg, name)["Instances"])


def _activities(asg, name):
    return [a for page in asg.get_paginator("describe_scaling_activities").paginate(
        AutoScalingGroupName=name) for a in page["Activities"]]


def _resume_all(asg, name):
    try:
        asg.resume_processes(AutoScalingGroupName=name)
    except ClientError as exc:
        err = exc.response.get("Error", {})
        # Already deleted by the graded leg: nothing to do.
        if err.get("Code") != "ValidationError" or "not found" not in err.get("Message", "").lower():
            raise


def _group(asg, name):
    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]
    assert groups, f"auto scaling group {name!r} not found"
    return groups[0]


def _group_or_none(asg, name):
    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]
    return groups[0] if groups else None


def _delete_group(asg, name):
    """Cleanup net: issue the ForceDelete and return without waiting, which would spend the whole
    60 s teardown budget; the graded leg in the body does the waiting."""
    try:
        asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    except ClientError as exc:
        if "not found" not in str(exc).lower():
            # Same exception type and code, so a caller catching ClientError still collects it.
            raise type(exc)(
                {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                    f"could not ForceDelete Auto Scaling group {name}: {exc}"
                )}},
                exc.operation_name,
            ) from exc


def _terminate_tagged_instances(ec2, name, *, wait, act=True, timeout_s=600.0):
    """Instances either group launched, found by the tag the launch template stamped at launch,
    that are not yet terminated. As a cleanup net (act=True, wait=False) it terminates them and
    returns at once; in the graded leg (act=False, wait=True) it only waits for EC2 to report them
    gone and returns whatever is still alive at the deadline."""
    def alive():
        return sorted(i["InstanceId"] for page in ec2.get_paginator("describe_instances").paginate(
            Filters=[{"Name": "tag:sim2real-asg", "Values": [name]},
                     {"Name": "instance-state-name",
                      "Values": ["pending", "running", "stopping", "stopped", "shutting-down"]}])
            for r in page["Reservations"] for i in r["Instances"])
    ids = alive()
    if act and ids:
        ec2.terminate_instances(InstanceIds=ids)
    if not wait:
        return ids
    deadline = time.monotonic() + timeout_s
    while ids and time.monotonic() < deadline:
        time.sleep(1)
        ids = alive()
    return ids


def _delete_when_idle(ctx, asg, name):
    """ForceDelete, retried only while Auto Scaling reports an activity still in progress."""
    deadline = time.monotonic() + _budget_s(ctx, 300.0)
    while True:
        try:
            asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
            return
        except ClientError as exc:
            if _code(exc) != "ScalingActivityInProgress" or time.monotonic() >= deadline:
                if _code(exc) == "ScalingActivityInProgress" and _budget_spent(ctx):
                    raise TimeoutError(f"ForceDelete of {name} once its activity ends: the run "
                                       "budget ended first; not graded") from exc
                raise
            time.sleep(2)



_GONE = ("InvalidVpcID.NotFound", "InvalidSubnetID.NotFound",
         "InvalidLaunchTemplateId.NotFound")


def _tags_for(name):
    return [{"Key": "sim2real", "Value": "1"}, {"Key": "Name", "Value": name}]


def _code(exc):
    return exc.response.get("Error", {}).get("Code")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(probe, predicate, *, timeout_s, interval_s, what, ctx=None):
    """Bounded poll that raises on timeout rather than returning its last observation."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{what}: the run budget ended first; not graded")
    raise AssertionError(f"{what} was not observed within {timeout_s}s; last saw {last!r}")


def _retry_dependency(fn, attempts=150, delay=2.0):
    for attempt in range(attempts):
        try:
            fn()
            return
        except ClientError as exc:
            if _code(exc) in _GONE:
                return
            if attempt == attempts - 1:
                raise RuntimeError(f"teardown step never converged: {exc}") from exc
            time.sleep(delay)


def _ec2_state(ec2, iid):
    try:
        resv = ec2.describe_instances(InstanceIds=[iid])["Reservations"]
    except ClientError as exc:
        if _code(exc) == "InvalidInstanceID.NotFound":
            return "__gone__"
        raise
    if not resv or not resv[0].get("Instances"):
        return "__gone__"
    return resv[0]["Instances"][0]["State"]["Name"]


def _zones_offering(ec2, instance_type):
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [instance_type]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers {instance_type!r}; offerings were {sorted(offered)!r}"
    return usable


def _network(ctx, ec2, name):
    vpc = ec2.create_vpc(CidrBlock=_VPC_CIDR, TagSpecifications=[
        {"ResourceType": "vpc", "Tags": _tags_for(name)}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc)))
    az = _zones_offering(ec2, _INSTANCE_TYPE)[0]
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock=_SUBNET_CIDR, AvailabilityZone=az,
                               TagSpecifications=[{"ResourceType": "subnet",
                                                   "Tags": _tags_for(name)}])["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _retry_dependency(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet)))
    return subnet


def _ami(ctx):
    ami = ctx.client("ssm").get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]["Value"]
    assert ami.startswith("ami-"), f"{_AL2023_AMI_PARAM} must resolve to an AMI id, got {ami!r}"
    return ami


# AWS-managed ENIs of resources in this VPC can outlive their owner's delete, so a network delete
# first waits (bounded) for the ENIs to go, retries DependencyViolation inside the same window, and
# then fails naming the ENIs still attached. The window is shared by all of one check's network
# deletes.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
