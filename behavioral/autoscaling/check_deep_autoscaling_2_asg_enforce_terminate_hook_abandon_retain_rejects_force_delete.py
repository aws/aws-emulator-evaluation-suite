"""deep-autoscaling-2-asg-enforce-terminate-hook-abandon-retain-rejects-force-delete."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-autoscaling-2-asg-enforce-terminate-hook-abandon-retain-rejects-force-delete"
GROUP = "instance-lifecycle-policy"
SERVICES = ["autoscaling"]


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """A group whose InstanceLifecyclePolicy sets TerminateHookAbandon=retain refuses ForceDelete
    with ValidationError (undeclared in the model) even without DeletionProtection; setting the
    trigger back to 'terminate' lets the identical ForceDelete through.
    """
    asg = ctx.client("autoscaling")
    subnet = _network(ctx)
    lt = _launch_template(ctx)
    name = ctx.unique_name("sim2real-asg-enf-rfd-")
    _create_group(ctx, name, subnet, lt, MinSize=0, MaxSize=1, DesiredCapacity=0,
                  InstanceLifecyclePolicy={"RetentionTriggers": {"TerminateHookAbandon": "retain"}})
    g = _group(asg, name)
    assert g.get("InstanceLifecyclePolicy") == {
        "RetentionTriggers": {"TerminateHookAbandon": "retain"}}, (
        f"InstanceLifecyclePolicy read back as {g.get('InstanceLifecyclePolicy')!r}"
    )
    # measured: a group created without DeletionProtection OMITS the field rather than
    # reporting 'none' — so nothing but the retention trigger can be what refuses below
    assert "DeletionProtection" not in g, (
        f"group created without protection reports DeletionProtection="
        f"{g.get('DeletionProtection')!r}; real AWS omits the field"
    )

    code, message = _error_code(lambda: asg.delete_auto_scaling_group(
        AutoScalingGroupName=name, ForceDelete=True))
    assert code == "ValidationError", f"ForceDelete with a retain trigger returned {code!r}"
    assert message == _RETAIN_TRIGGER_MESSAGE, f"ForceDelete with a retain trigger said {message!r}"
    g = _group_or_none(asg, name)
    assert g is not None, f"group {name!r} disappeared after the refused ForceDelete"
    assert g.get("Status") is None, f"group entered status {g.get('Status')!r} after refusal"
    assert g.get("InstanceLifecyclePolicy") == {
        "RetentionTriggers": {"TerminateHookAbandon": "retain"}}, (
        f"refusal altered the policy to {g.get('InstanceLifecyclePolicy')!r}"
    )

    # positive control: flip the one trigger, and the identical request is accepted
    asg.update_auto_scaling_group(
        AutoScalingGroupName=name,
        InstanceLifecyclePolicy={"RetentionTriggers": {"TerminateHookAbandon": "terminate"}})
    asg.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    _poll_until(lambda: _group_or_none(asg, name), lambda x: x is None,
                timeout_s=300, interval_s=5)

    _drain(ctx, [name])



_RETAIN_TRIGGER_MESSAGE = (
    "You can't force delete this Auto Scaling group because the TerminateHookAbandon retention "
    "trigger is set to retain. Change the retention trigger to terminate and try again."
)



def _error_code(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
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
    """Fast cleanup without waiting: lift every deletion guard, ForceDelete, and terminate any
    instance still carrying the group tag (a retained instance outlives its group, and a
    protected one is not drained by scale-in)."""
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
        # issued (measured: they sit in Terminating:Wait for the full heartbeat). Deleting the
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
    """Release every group, wait until each is gone and its instances are terminated at EC2,
    then run the registered cleanups (launch template, subnet, VPC) while ENI-release waits fit."""
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
