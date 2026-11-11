"""lifecycle-hook-heartbeat-complete-order."""
from __future__ import annotations

from botocore.exceptions import ClientError


from behavioral_harness import tags


CHECK = "lifecycle-hook-heartbeat-complete-order"
GROUP = 'ordering'
SERVICES = ['autoscaling']


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutLifecycleHook pauses a launching instance in Pending:Wait; a heartbeat while
    waiting must NOT itself advance the instance; only the subsequent CompleteLifecycleAction
    releases it — heartbeat-before-complete is the only order that makes sense here."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    def _poll_until(probe, pred, timeout_s=120, interval_s=3, description="condition"):
        import time
        deadline = time.monotonic() + timeout_s
        last = None
        while time.monotonic() < deadline:
            last = probe()
            if pred(last):
                return last
            time.sleep(interval_s)
        raise AssertionError(f"{description} not met within {timeout_s}s; last result: {last!r}")

    def _image_id():
        param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        try:
            return ssm.get_parameter(Name=param)["Parameter"]["Value"]
        except Exception:
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

    def _describe_group(name):
        groups = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[name]).get(
            "AutoScalingGroups", []
        )
        return groups[0] if groups else None

    def _group_instances(name):
        g = _describe_group(name)
        return g.get("Instances", []) if g else []

    def _describe_asg_instances(instance_ids):
        return as_.describe_auto_scaling_instances(InstanceIds=instance_ids).get(
            "AutoScalingInstances", []
        )

    def _make_lt(instance_type="t3.micro"):
        lt_name = ctx.unique_name("sim2real-behav-as-lt-")
        ec2.create_launch_template(
            LaunchTemplateName=lt_name,
            LaunchTemplateData={"ImageId": _image_id(), "InstanceType": instance_type},
            TagSpecifications=[
                {
                    "ResourceType": "launch-template",
                    "Tags": [{"Key": "sim2real-behav-check", "Value": CHECK}],
                }
            ],
        )
        ctx.on_cleanup(lambda n=lt_name: ec2.delete_launch_template(LaunchTemplateName=n))
        return lt_name

    def _make_asg(min_size=0, max_size=1, desired_capacity=0, launch_template_name=None, **kwargs):
        if launch_template_name is None:
            launch_template_name = _make_lt()
        asg_name = ctx.unique_name("sim2real-behav-as-grp-")
        params = {
            "AutoScalingGroupName": asg_name,
            "LaunchTemplate": {"LaunchTemplateName": launch_template_name, "Version": "$Latest"},
            "MinSize": min_size,
            "MaxSize": max_size,
            "DesiredCapacity": desired_capacity,
            "VPCZoneIdentifier": ",".join(_subnet_ids()),
            "HealthCheckGracePeriod": 0,
            "Tags": [
                {
                    "ResourceId": asg_name,
                    "ResourceType": "auto-scaling-group",
                    "Key": "sim2real-behav-check",
                    "Value": CHECK,
                    "PropagateAtLaunch": False,
                }
            ],
        }
        params.update(kwargs)
        as_.create_auto_scaling_group(**params)
        ctx.on_cleanup(
            lambda n=asg_name: as_.delete_auto_scaling_group(
                AutoScalingGroupName=n, ForceDelete=True
            )
        )
        return asg_name

    def _error(fn):
        """Call fn(); return its ClientError (code, message). An unexpected SUCCESS raises, because
        an emulator accepting input real AWS refuses is the strongest signal available."""
        try:
            result = fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
        raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")

    name = _make_asg(min_size=0, max_size=2, desired_capacity=0)
    hook_name = ctx.unique_name("sim2real-behav-hook-")
    as_.put_lifecycle_hook(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=name,
        LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
        DefaultResult="ABANDON",
        HeartbeatTimeout=600,
    )

    as_.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=1, HonorCooldown=False)

    target = _poll_until(
        lambda: next((i for i in _group_instances(name) if i.get("LifecycleState") == "Pending:Wait"), None),
        lambda i: i is not None,
        timeout_s=120,
        interval_s=3,
        description=f"instance paused in Pending:Wait for hook {hook_name}",
    )
    instance_id = target["InstanceId"]

    # Order step 1: heartbeat is accepted while waiting, and must NOT by itself release it.
    as_.record_lifecycle_action_heartbeat(
        LifecycleHookName=hook_name, AutoScalingGroupName=name, InstanceId=instance_id
    )
    still_waiting = _describe_asg_instances([instance_id])
    assert still_waiting and still_waiting[0]["LifecycleState"] == "Pending:Wait", (
        "a heartbeat must not itself advance the instance out of the wait state"
    )

    # Order step 2: only AFTER the heartbeat does CompleteLifecycleAction release it.
    as_.complete_lifecycle_action(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=name,
        InstanceId=instance_id,
        LifecycleActionResult="CONTINUE",
    )
    _poll_until(
        lambda: _describe_asg_instances([instance_id]),
        lambda insts: bool(insts) and insts[0]["LifecycleState"] not in ("Pending:Wait", "Pending"),
        timeout_s=60,
        interval_s=2,
        description=f"instance {instance_id} proceeded past the hook after completion",
    )

    # Overly-permissive guard: PutLifecycleHook with an invalid DefaultResult must be
    # rejected outright rather than silently stored with a bogus fallback action.
    bad_hook = ctx.unique_name("sim2real-behav-hook-bad-")
    code, message = _error(
        lambda: as_.put_lifecycle_hook(
            LifecycleHookName=bad_hook,
            AutoScalingGroupName=name,
            LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
            DefaultResult="NOT_A_REAL_RESULT",
        )
    )
    assert code == "ValidationError", f"expected ValidationError for an invalid DefaultResult, got {code!r}"
    expected = "'DefaultResult' must be one of: CONTINUE, ABANDON"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent: the rejected hook must not exist -- confirmed via an independent read
    # (DescribeLifecycleHooks), not by trusting the mutating call's own exception.
    hooks_after = as_.describe_lifecycle_hooks(AutoScalingGroupName=name)["LifecycleHooks"]
    assert not any(h["LifecycleHookName"] == bad_hook for h in hooks_after), (
        f"a PutLifecycleHook rejected with ValidationError still created hook {bad_hook!r}: "
        f"{hooks_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
