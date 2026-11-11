"""lifecycle-hook-timeout-applies-default-result."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "lifecycle-hook-timeout-applies-default-result"
GROUP = 'lifecycle-hooks'
SERVICES = ['autoscaling']


def _poll(fn, pred, *, timeout_s, interval_s=5, description="condition"):
    """Poll ``fn`` until ``pred`` holds; raise with the last observed value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = fn()
    while not pred(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)
        last = fn()
    return last


# timing:real-time — workflow: 30 s https://docs.aws.amazon.com/autoscaling/ec2/userguide/lifecycle-hooks.html
@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:data-plane",
    "dp:api",
    "plane:control",
    "plane:data",
    "timing:real-time",
)
def run(ctx) -> None:
    """An expired lifecycle hook HeartbeatTimeout makes Auto Scaling apply the hook's DefaultResult:
    CONTINUE releases the instance to InService; ABANDON terminates it, never InService."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    def _image_id():
        param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        try:
            return ssm.get_parameter(Name=param)["Parameter"]["Value"]
        except ClientError:
            imgs = sorted(
                ec2.describe_images(
                    Owners=["amazon"],
                    Filters=[
                        {"Name": "name", "Values": ["al2023-ami-kernel-default-x86_64*"]},
                        {"Name": "state", "Values": ["available"]},
                    ],
                ).get("Images", []),
                key=lambda i: i.get("CreationDate", ""),
            )
            if not imgs:
                raise AssertionError("no Amazon Linux 2023 AMI available in this region")
            return imgs[-1]["ImageId"]

    def _subnet_ids():
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        ).get("Subnets", [])
        if not subnets:
            raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
        return [s["SubnetId"] for s in sorted(subnets, key=lambda s: s["AvailabilityZone"])[:2]]

    def _make_lt():
        lt_name = ctx.unique_name("sim2real-behav-as-lt-")
        ec2.create_launch_template(
            LaunchTemplateName=lt_name,
            LaunchTemplateData={"ImageId": _image_id(), "InstanceType": "t3.micro"},
            TagSpecifications=[
                {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
            ],
        )
        ctx.on_cleanup(lambda n=lt_name: ec2.delete_launch_template(LaunchTemplateName=n))
        return lt_name

    def _teardown_asg(name):
        # Drain capacity to zero before ForceDelete: an ABANDON hook keeps the group relaunching.
        try:
            as_.update_auto_scaling_group(
                AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0
            )
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
                return
            raise
        as_.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)

    def _make_asg(min_size, max_size, desired_capacity, **kwargs):
        asg_name = ctx.unique_name("sim2real-behav-as-grp-")
        params = {
            "AutoScalingGroupName": asg_name,
            "LaunchTemplate": {"LaunchTemplateName": _make_lt(), "Version": "$Latest"},
            "MinSize": min_size,
            "MaxSize": max_size,
            "DesiredCapacity": desired_capacity,
            "VPCZoneIdentifier": ",".join(_subnet_ids()),
            "HealthCheckGracePeriod": 0,
            "Tags": [{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
        }
        params.update(kwargs)
        as_.create_auto_scaling_group(**params)
        ctx.on_cleanup(lambda n=asg_name: _teardown_asg(n))
        return asg_name

    def _group(name):
        groups = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[name]).get(
            "AutoScalingGroups", []
        )
        return groups[0] if groups else None

    def _instances(name):
        g = _group(name)
        return g.get("Instances", []) if g else []

    def _state(name, instance_id):
        for inst in _instances(name):
            if inst["InstanceId"] == instance_id:
                return inst.get("LifecycleState")
        return None

    def _waiting(name, exclude=()):
        for inst in _instances(name):
            if inst.get("LifecycleState") == "Pending:Wait" and inst["InstanceId"] not in exclude:
                return inst
        return None

    def _ec2_state(instance_id):
        for page in ec2.get_paginator("describe_instances").paginate(InstanceIds=[instance_id]):
            for res in page["Reservations"]:
                for inst in res["Instances"]:
                    if inst["InstanceId"] == instance_id:
                        return inst["State"]["Name"]
        raise AssertionError(f"instance {instance_id!r} not found in DescribeInstances")

    name = _make_asg(0, 2, 0)

    # ---- Branch 1: DefaultResult=CONTINUE. Nobody completes the action; the 30s heartbeat
    #      timeout must expire and Auto Scaling must release the instance on its own.
    hook_continue = ctx.unique_name("sim2real-behav-hook-continue-")
    as_.put_lifecycle_hook(
        LifecycleHookName=hook_continue,
        AutoScalingGroupName=name,
        LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
        DefaultResult="CONTINUE",
        HeartbeatTimeout=30,
    )
    hooks = as_.describe_lifecycle_hooks(
        AutoScalingGroupName=name, LifecycleHookNames=[hook_continue]
    )["LifecycleHooks"]
    assert len(hooks) == 1, f"expected the CONTINUE hook to be stored, got {hooks}"
    assert hooks[0]["HeartbeatTimeout"] == 30, hooks[0].get("HeartbeatTimeout")
    assert hooks[0]["DefaultResult"] == "CONTINUE", hooks[0].get("DefaultResult")

    as_.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=1, HonorCooldown=False)
    paused = _poll(
        lambda: _waiting(name),
        lambda i: i is not None,
        timeout_s=300,
        interval_s=3,
        description=f"an instance paused in Pending:Wait for hook {hook_continue}",
    )
    first_id = paused["InstanceId"]
    wait_started = time.monotonic()

    released = _poll(
        lambda: _state(name, first_id),
        lambda s: s == "InService",
        timeout_s=300,
        interval_s=5,
        description=(
            f"the 30s heartbeat timeout expired and DefaultResult=CONTINUE released {first_id} "
            "without any CompleteLifecycleAction"
        ),
    )
    assert released == "InService", (
        f"a timed-out CONTINUE hook must place {first_id} InService, final state was {released!r}"
    )

    # Two-sided clock: a target that ignores HeartbeatTimeout and releases the instance almost
    # immediately (never actually holding it for the hook's 30s) must fail this just as much as one
    # that never releases it at all. 20s tolerates the poll's own detection lag on both ends.
    held_for = time.monotonic() - wait_started
    assert held_for >= 20, (
        f"instance {first_id} left Pending:Wait after only {held_for:.1f}s; a 30s HeartbeatTimeout "
        "must be honored before DefaultResult is applied, not bypassed"
    )

    # Confirm at EC2 that the instance is running; polled because ASG and EC2 state are
    # eventually consistent with each other.
    ec2_state = _poll(
        lambda: _ec2_state(first_id),
        lambda s: s == "running",
        timeout_s=60,
        interval_s=5,
        description=f"EC2 DescribeInstances agreeing {first_id} is running",
    )
    assert ec2_state == "running", (
        f"ASG reports {first_id} InService but EC2 DescribeInstances says {ec2_state!r}"
    )
    as_.delete_lifecycle_hook(LifecycleHookName=hook_continue, AutoScalingGroupName=name)

    # ---- Branch 2: DefaultResult=ABANDON on the same transition. The next instance must be
    #      terminated by the timeout and must NEVER be placed InService.
    hook_abandon = ctx.unique_name("sim2real-behav-hook-abandon-")
    as_.put_lifecycle_hook(
        LifecycleHookName=hook_abandon,
        AutoScalingGroupName=name,
        LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
        DefaultResult="ABANDON",
        HeartbeatTimeout=30,
    )
    as_.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=2, HonorCooldown=False)
    paused2 = _poll(
        lambda: _waiting(name, exclude=(first_id,)),
        lambda i: i is not None,
        timeout_s=300,
        interval_s=3,
        description=f"a second instance paused in Pending:Wait for hook {hook_abandon}",
    )
    second_id = paused2["InstanceId"]
    wait_started_2 = time.monotonic()

    seen = []

    def _probe_second():
        state = _state(name, second_id)
        seen.append(state)
        return state

    final = _poll(
        _probe_second,
        lambda s: s is None or s == "Terminated" or (s or "").startswith("Terminating"),
        timeout_s=300,
        interval_s=5,
        description=(
            f"the 30s heartbeat timeout expired and DefaultResult=ABANDON terminated {second_id}"
        ),
    )
    assert final is None or final == "Terminated" or final.startswith("Terminating"), (
        f"a timed-out ABANDON hook must terminate {second_id}, final state was {final!r}"
    )
    assert "InService" not in seen, (
        f"an ABANDON'd instance must never be placed InService; observed states {seen}"
    )

    # Same two-sided clock as branch 1: the termination must follow a real 30s hold, not a hook
    # that abandons on sight.
    held_for_2 = time.monotonic() - wait_started_2
    assert held_for_2 >= 20, (
        f"instance {second_id} left Pending:Wait after only {held_for_2:.1f}s; a 30s "
        "HeartbeatTimeout must be honored before DefaultResult=ABANDON is applied"
    )

    # Confirm at EC2 that the abandoned instance is actually gone; polled for eventual consistency.
    ec2_state_2 = _poll(
        lambda: _ec2_state(second_id),
        lambda s: s in ("shutting-down", "terminated"),
        timeout_s=180,
        interval_s=5,
        description=f"EC2 DescribeInstances agreeing {second_id} is terminating or terminated",
    )
    assert ec2_state_2 in ("shutting-down", "terminated"), (
        f"ASG abandoned {second_id} but EC2 DescribeInstances says {ec2_state_2!r}"
    )

    # Stop the abandon/relaunch churn before teardown so no instance is left mid-launch.
    as_.delete_lifecycle_hook(LifecycleHookName=hook_abandon, AutoScalingGroupName=name)
    as_.update_auto_scaling_group(
        AutoScalingGroupName=name, MinSize=0, MaxSize=1, DesiredCapacity=0
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
