"""lifecycle-hook-heartbeat-timeout-extension."""
from __future__ import annotations

import time


from behavioral_harness import tags


CHECK = "lifecycle-hook-heartbeat-timeout-extension"
GROUP = 'visibility-timeout-ttl'
SERVICES = ['autoscaling']


# timing:real-time — workflow: 30 s https://docs.aws.amazon.com/autoscaling/ec2/userguide/lifecycle-hooks.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """RecordLifecycleActionHeartbeat extends the hook's HeartbeatTimeout window: an
    instance that is heartbeated part-way through a short timeout is STILL waiting well
    past when the ORIGINAL window would have expired it — proof the countdown reset."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    def _poll_until(probe, pred, timeout_s=120, interval_s=3, description="condition"):
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
                {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": CHECK}]}
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
            "Tags": [{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": True}],
        }
        params.update(kwargs)
        as_.create_auto_scaling_group(**params)
        ctx.on_cleanup(
            lambda n=asg_name: as_.delete_auto_scaling_group(
                AutoScalingGroupName=n, ForceDelete=True
            )
        )
        return asg_name

    name = _make_asg(min_size=0, max_size=2, desired_capacity=0)
    hook_name = ctx.unique_name("sim2real-behav-hook-")
    as_.put_lifecycle_hook(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=name,
        LifecycleTransition="autoscaling:EC2_INSTANCE_LAUNCHING",
        DefaultResult="ABANDON",
        HeartbeatTimeout=30,
    )
    hooks = as_.describe_lifecycle_hooks(
        AutoScalingGroupName=name, LifecycleHookNames=[hook_name]
    )["LifecycleHooks"]
    assert hooks[0]["HeartbeatTimeout"] == 30, (
        f"expected the hook's stored HeartbeatTimeout to be 30, got {hooks[0].get('HeartbeatTimeout')!r}"
    )

    as_.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=1, HonorCooldown=False)
    target = _poll_until(
        lambda: next((i for i in _group_instances(name) if i.get("LifecycleState") == "Pending:Wait"), None),
        lambda i: i is not None,
        timeout_s=120,
        interval_s=3,
        description=f"instance paused on hook {hook_name}",
    )
    instance_id = target["InstanceId"]

    # Heartbeat near the edge of the original 30s window — poll (rather than blindly
    # sleep) so a premature abandonment would be caught immediately instead of only
    # discovered after the fact.
    approach_start = time.monotonic()

    def _probe_before_heartbeat():
        insts = _describe_asg_instances([instance_id])
        assert insts and insts[0]["LifecycleState"] == "Pending:Wait", (
            f"instance must remain Pending:Wait while approaching the original "
            f"HeartbeatTimeout, got {insts!r}"
        )
        return time.monotonic() - approach_start

    # The window is measured from the first observed Pending:Wait, which lags the hook's own
    # start by up to one poll interval plus a round trip, so the heartbeat lands at 15 s.
    _poll_until(
        _probe_before_heartbeat,
        lambda elapsed: elapsed >= 15,
        timeout_s=40,
        interval_s=2,
        description="approach the edge of the original 30s HeartbeatTimeout while still waiting",
    )

    as_.record_lifecycle_action_heartbeat(
        LifecycleHookName=hook_name, AutoScalingGroupName=name, InstanceId=instance_id
    )

    # ...and confirm the instance STAYS Pending:Wait well past when the ORIGINAL 30s
    # timeout would have expired/abandoned it — proof the heartbeat extended the window.
    extend_start = time.monotonic()

    def _probe_after_heartbeat():
        insts = _describe_asg_instances([instance_id])
        assert insts and insts[0]["LifecycleState"] == "Pending:Wait", (
            f"the heartbeat must have extended the wait window, but the instance left "
            f"Pending:Wait before the extended window elapsed: {insts!r}"
        )
        return time.monotonic() - extend_start

    # The original window ends at most 15 s after the heartbeat and the reset one 30 s after it;
    # holding 22 s passes the first and stays clear of the second.
    _poll_until(
        _probe_after_heartbeat,
        lambda elapsed: elapsed >= 22,
        timeout_s=40,
        interval_s=2,
        description="stay Pending:Wait for 22s after the heartbeat, past the ORIGINAL 30s timeout, proving the heartbeat extended it",
    )

    # Release the instance and confirm CompleteLifecycleAction actually took effect --
    # an independent read at the destination, not the mutating call's own response.
    as_.complete_lifecycle_action(
        LifecycleHookName=hook_name,
        AutoScalingGroupName=name,
        InstanceId=instance_id,
        LifecycleActionResult="CONTINUE",
    )
    resolved = _poll_until(
        lambda: next(
            (i["LifecycleState"] for i in _group_instances(name) if i["InstanceId"] == instance_id),
            None,
        ),
        lambda state: state == "InService",
        timeout_s=120,
        interval_s=3,
        description=f"instance {instance_id} released to InService after CompleteLifecycleAction",
    )
    assert resolved == "InService", (
        f"expected {instance_id} to resolve to InService after CONTINUE, got {resolved!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
