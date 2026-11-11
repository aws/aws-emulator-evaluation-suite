"""deep-autoscaling-2-asg-enforce-terminate-hook-abandon-retain-keeps-instance-outside-desired."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-autoscaling-2-asg-enforce-terminate-hook-abandon-retain-keeps-instance-outside-desired"
GROUP = "instance-lifecycle-policy"
SERVICES = ["autoscaling"]

_HOOK = "sim2real-terminate-hook"


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "dp:api",
    "plane:control",
    "plane:data",
)
def run(ctx) -> None:
    """With TerminateHookAbandon=retain, a terminating hook's ABANDON parks the instance in
    Terminating:Retained (running, outside desired, replaced) while an unretained twin terminates;
    TerminateInstanceInAutoScalingGroup then clears it through the hook again.
    """
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    subnet = _network(ctx)
    lt = _launch_template(ctx)
    hook = [{"LifecycleHookName": _HOOK,
             "LifecycleTransition": "autoscaling:EC2_INSTANCE_TERMINATING",
             "DefaultResult": "ABANDON", "HeartbeatTimeout": 900}]
    control = ctx.unique_name("sim2real-asg-enf-rkc-")
    subject = ctx.unique_name("sim2real-asg-enf-rks-")
    _create_group(ctx, control, subnet, lt, MinSize=0, MaxSize=2, DesiredCapacity=1,
                  LifecycleHookSpecificationList=hook)
    _create_group(ctx, subject, subnet, lt, MinSize=0, MaxSize=2, DesiredCapacity=1,
                  LifecycleHookSpecificationList=hook,
                  InstanceLifecyclePolicy={"RetentionTriggers": {"TerminateHookAbandon": "retain"}})

    def one_in_service(d):
        return len(d) == 1 and all(i["LifecycleState"] == "InService" for i in d.values())

    c_iid = next(iter(_poll_until(lambda: _instances(asg, control), one_in_service,
                                  timeout_s=480, interval_s=10)))
    s_iid = next(iter(_poll_until(lambda: _instances(asg, subject), one_in_service,
                                  timeout_s=480, interval_s=10)))

    for grp, iid in ((control, c_iid), (subject, s_iid)):
        asg.terminate_instance_in_auto_scaling_group(
            InstanceId=iid, ShouldDecrementDesiredCapacity=False)
    for grp, iid in ((control, c_iid), (subject, s_iid)):
        _poll_until(lambda g=grp, i=iid: _instances(asg, g).get(i, {}).get("LifecycleState"),
                    lambda s: s == "Terminating:Wait", timeout_s=300, interval_s=5)
        asg.complete_lifecycle_action(LifecycleHookName=_HOOK, AutoScalingGroupName=grp,
                                      InstanceId=iid, LifecycleActionResult="ABANDON")

    # subject: ABANDON is retained, not terminated
    _poll_until(lambda: _instances(asg, subject).get(s_iid, {}).get("LifecycleState"),
                lambda s: s == "Terminating:Retained", timeout_s=300, interval_s=5)

    # control: ABANDON terminates — the instance leaves the group and is terminated at EC2
    _poll_until(lambda: c_iid in _instances(asg, control), lambda present: present is False,
                timeout_s=600, interval_s=10)
    _poll_until(lambda: _ec2_state(ec2, c_iid), lambda s: s == "terminated",
                timeout_s=300, interval_s=10)

    # retained instance does not count toward desired: a replacement launches alongside it
    s_insts = _poll_until(
        lambda: _instances(asg, subject),
        lambda d: any(k != s_iid and v["LifecycleState"] == "InService" for k, v in d.items()),
        timeout_s=480, interval_s=10)
    assert s_insts[s_iid]["LifecycleState"] == "Terminating:Retained", (
        f"retained instance moved to {s_insts[s_iid]['LifecycleState']!r} while replacing"
    )
    assert len(s_insts) == 2, f"subject group holds {sorted(s_insts)!r}, expected retained+replacement"
    g = _group(asg, subject)
    assert g["DesiredCapacity"] == 1, f"subject desired drifted to {g['DesiredCapacity']!r}"
    st = _ec2_state(ec2, s_iid)
    assert st == "running", f"retained instance {s_iid!r} is {st!r} at EC2, expected running"

    # only TerminateInstanceInAutoScalingGroup clears the retained instance — and that
    # termination runs the terminating hook AGAIN (without a completion it sits in
    # Terminating:Wait for the whole heartbeat), so it is released with CONTINUE.
    asg.terminate_instance_in_auto_scaling_group(
        InstanceId=s_iid, ShouldDecrementDesiredCapacity=False)
    _poll_until(lambda: _instances(asg, subject).get(s_iid, {}).get("LifecycleState"),
                lambda s: s == "Terminating:Wait", timeout_s=300, interval_s=5)
    asg.complete_lifecycle_action(LifecycleHookName=_HOOK, AutoScalingGroupName=subject,
                                  InstanceId=s_iid, LifecycleActionResult="CONTINUE")
    _poll_until(lambda: s_iid in _instances(asg, subject), lambda present: present is False,
                timeout_s=600, interval_s=10)
    _poll_until(lambda: _ec2_state(ec2, s_iid), lambda s: s == "terminated",
                timeout_s=300, interval_s=10)
    left = {k: v["LifecycleState"] for k, v in _instances(asg, subject).items()}
    assert len(left) == 1 and list(left.values()) == ["InService"], (
        f"after clearing the retained instance the subject holds {left!r}"
    )

    _drain(ctx, [subject, control])




def _error_code(fn) -> str:
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    raise AssertionError("call unexpectedly SUCCEEDED where real AWS refuses it")


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _group_or_none(asg, name):
    groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[name])["AutoScalingGroups"]
    return groups[0] if groups else None


def _group(asg, name):
    g = _group_or_none(asg, name)
    assert g is not None, f"group {name!r} not found"
    return g


def _instances(asg, name) -> dict:
    return {i["InstanceId"]: i for i in _group(asg, name)["Instances"]}


def _ec2_state(ec2, iid) -> str:
    res = ec2.describe_instances(InstanceIds=[iid])["Reservations"]
    return res[0]["Instances"][0]["State"]["Name"]


def _network(ctx) -> str:
    ec2 = ctx.client("ec2")
    tag = [{"Key": "sim2real", "Value": CHECK[:200]}]
    vpc = ec2.create_vpc(CidrBlock="10.91.0.0/16",
                         TagSpecifications=[{"ResourceType": "vpc", "Tags": tag}])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc))
    want = "t3.micro"
    offered = {o["Location"] for o in ec2.describe_instance_type_offerings(
        LocationType="availability-zone",
        Filters=[{"Name": "instance-type", "Values": [want]}])["InstanceTypeOfferings"]}
    usable = sorted(z["ZoneName"] for z in ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}])["AvailabilityZones"]
        if z["ZoneName"] in offered)
    assert usable, f"no available AZ offers {want!r}; offerings were {sorted(offered)!r}"
    subnet = ec2.create_subnet(VpcId=vpc, CidrBlock="10.91.1.0/24", AvailabilityZone=usable[0],
                               TagSpecifications=[{"ResourceType": "subnet", "Tags": tag}]
                               )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_subnet(ec2, subnet))
    return subnet


def _delete_subnet(ec2, subnet) -> None:
    deadline = time.monotonic() + 300
    while True:
        try:
            ec2.delete_subnet(SubnetId=subnet)
            return
        except ClientError as err:
            # ENIs of just-terminated instances detach asynchronously after termination.
            if err.response["Error"]["Code"] != "DependencyViolation" or time.monotonic() > deadline:
                raise
            time.sleep(10)


def _launch_template(ctx) -> str:
    ec2 = ctx.client("ec2")
    ami = ctx.client("ssm").get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]
    name = ctx.unique_name("sim2real-asg-enf-lt-")
    tag = [{"Key": "sim2real:lt", "Value": name}]
    ec2.create_launch_template(
        LaunchTemplateName=name,
        LaunchTemplateData={
            "ImageId": ami,
            "InstanceType": "t3.micro",
            "TagSpecifications": [{"ResourceType": "instance", "Tags": tag},
                                  {"ResourceType": "volume", "Tags": tag}],
        },
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": tag}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=name))
    return name


def _create_group(ctx, name, subnet, lt, **kw) -> None:
    asg = ctx.client("autoscaling")
    asg.create_auto_scaling_group(
        AutoScalingGroupName=name,
        LaunchTemplate={"LaunchTemplateName": lt, "Version": "$Latest"},
        VPCZoneIdentifier=subnet,
        Tags=[{"Key": "sim2real", "Value": name, "PropagateAtLaunch": True}],
        **kw,
    )
    ctx.on_cleanup(lambda: _release_group(ctx, name))


def _group_not_found(exc) -> bool:
    error = exc.response.get("Error", {})
    return error.get("Code") == "ValidationError" and "not found" in error.get("Message", "")


def _release_group(ctx, name) -> None:
    """FAST net, no waiting: the engine bounds the whole cleanup chain at 60 s. Lift every
    deletion guard, ForceDelete, and terminate any instance still carrying the group tag (a
    retained instance outlives its group, and a protected one is not drained by scale-in)."""
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    if _group_or_none(asg, name) is not None:
        try:
            asg.update_auto_scaling_group(
                AutoScalingGroupName=name, DeletionProtection="none",
                InstanceLifecyclePolicy={"RetentionTriggers": {"TerminateHookAbandon": "terminate"}})
        except ClientError as exc:
            if not _group_not_found(exc):
                raise
        # ForceDelete does NOT bypass a terminating hook for instances still InService when it is
        # issued (they sit in Terminating:Wait for the full heartbeat). Deleting the
        # hook first lets termination proceed.
        try:
            for h in asg.describe_lifecycle_hooks(AutoScalingGroupName=name)["LifecycleHooks"]:
                asg.delete_lifecycle_hook(LifecycleHookName=h["LifecycleHookName"],
                                          AutoScalingGroupName=name)
        except ClientError as exc:
            if not _group_not_found(exc):
                raise
        for attempt in range(3):
            try:
                asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
                break
            except ClientError:
                if _group_or_none(asg, name) is None:
                    break
                if attempt == 2:
                    raise
                time.sleep(5)
    filt = [{"Name": "tag:aws:autoscaling:groupName", "Values": [name]},
            {"Name": "instance-state-name",
             "Values": ["pending", "running", "stopping", "stopped"]}]
    ids = [i["InstanceId"] for r in ec2.describe_instances(Filters=filt)["Reservations"]
           for i in r["Instances"]]
    if ids:
        ec2.terminate_instances(InstanceIds=ids)


def _drain(ctx, names) -> None:
    """Teardown inside the check's own budget: release every group, wait until each is gone and
    its instances are terminated at EC2, then run the registered nets (launch template, subnet,
    VPC) now, while their ENI-release waits still fit, instead of in the 60 s cleanup window."""
    asg = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    for n in names:
        _release_group(ctx, n)
    for n in names:
        _poll_until(lambda n=n: _group_or_none(asg, n), lambda x: x is None,
                    timeout_s=900, interval_s=10)
    filt = [{"Name": "tag:aws:autoscaling:groupName", "Values": list(names)}]
    ids = [i["InstanceId"] for r in ec2.describe_instances(Filters=filt)["Reservations"]
           for i in r["Instances"] if i["State"]["Name"] != "terminated"]
    if ids:
        ec2.terminate_instances(InstanceIds=ids)
        ec2.get_waiter("instance_terminated").wait(
            InstanceIds=ids, WaiterConfig={"Delay": 2, "MaxAttempts": 200})
    ctx.run_cleanups()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
