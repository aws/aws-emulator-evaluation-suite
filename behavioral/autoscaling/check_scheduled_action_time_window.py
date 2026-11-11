"""scheduled-action-time-window."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError


from behavioral_harness import tags


CHECK = "scheduled-action-time-window"
GROUP = 'overly-permissive'
SERVICES = ['autoscaling']


# timing:real-time — schedule: 75 s https://docs.aws.amazon.com/autoscaling/ec2/userguide/ec2-auto-scaling-scheduled-scaling.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A scheduled action must be inert BEFORE its StartTime and take effect only once
    the StartTime/EndTime window opens — DescribeScheduledActions round-trips the exact
    window, and DesiredCapacity is untouched until that window actually opens."""
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

    def _make_lt(instance_type="t3.micro"):
        lt_name = ctx.unique_name("sim2real-behav-as-lt-")
        ec2.create_launch_template(
            LaunchTemplateName=lt_name,
            LaunchTemplateData={"ImageId": _image_id(), "InstanceType": instance_type},
            TagSpecifications=[
                {"ResourceType": "launch-template", "Tags": [{"Key": "sim2real:managed", "Value": "true"}]}
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
            "Tags": [{"Key": "sim2real:managed", "Value": "true", "PropagateAtLaunch": True}],
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
        """(error code, error message) fn() raises; an unexpected SUCCESS raises."""
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")

    name = _make_asg(min_size=0, max_size=5, desired_capacity=1)
    action_name = ctx.unique_name("sim2real-behav-sched-window-")
    start_time = datetime.now(timezone.utc) + timedelta(seconds=75)
    end_time = start_time + timedelta(minutes=10)

    as_.put_scheduled_update_group_action(
        AutoScalingGroupName=name,
        ScheduledActionName=action_name,
        StartTime=start_time,
        EndTime=end_time,
        DesiredCapacity=3,
        MinSize=1,
        MaxSize=5,
    )
    described = as_.describe_scheduled_actions(
        AutoScalingGroupName=name, ScheduledActionNames=[action_name]
    )
    action = described["ScheduledUpdateGroupActions"][0]
    assert action["DesiredCapacity"] == 3, f"expected DesiredCapacity 3 to round-trip, got {action['DesiredCapacity']!r}"
    assert abs((action["StartTime"] - start_time).total_seconds()) < 2, "StartTime must round-trip exactly"
    assert abs((action["EndTime"] - end_time).total_seconds()) < 2, "EndTime must round-trip exactly"

    # Before StartTime, the window has not opened — group capacity must be untouched.
    before = _describe_group(name)
    assert before["DesiredCapacity"] == 1, "a scheduled action must not apply before its StartTime"

    # After StartTime passes, Auto Scaling applies the action and DesiredCapacity becomes 3.
    after = _poll_until(
        lambda: _describe_group(name),
        lambda g: g["DesiredCapacity"] == 3,
        timeout_s=180,
        interval_s=5,
        description=f"scheduled action {action_name} applied once its StartTime window opened",
    )
    assert after["DesiredCapacity"] == 3, f"expected DesiredCapacity 3 once the window opened, got {after['DesiredCapacity']!r}"

    # Overly-permissive guard: an EndTime before StartTime describes an empty/invalid
    # window and must be rejected outright, not silently accepted.
    # Both bounds lie in the future, so the only defect is their order (an EndTime already in
    # the past is refused for that reason first).
    bad_action = ctx.unique_name("sim2real-behav-sched-badwindow-")
    bad_start = datetime.now(timezone.utc) + timedelta(days=2)
    code, message = _error(
        lambda: as_.put_scheduled_update_group_action(
            AutoScalingGroupName=name,
            ScheduledActionName=bad_action,
            StartTime=bad_start,
            EndTime=bad_start - timedelta(days=1),
            DesiredCapacity=2,
        )
    )
    assert code == "ValidationError", f"expected ValidationError for EndTime before StartTime, got {code!r}"
    assert message == "Given end time must be after start time", (
        f"unexpected ValidationError message for EndTime before StartTime: {message!r}"
    )
    remaining_names = {
        a["ScheduledActionName"]
        for a in as_.describe_scheduled_actions(AutoScalingGroupName=name)["ScheduledUpdateGroupActions"]
    }
    assert bad_action not in remaining_names, (
        f"a rejected PutScheduledUpdateGroupAction must create no action, but {bad_action!r} "
        f"is present: {remaining_names!r}"
    )

    # Best-effort cleanup: a one-time (non-recurring) scheduled action is automatically
    # removed by Auto Scaling once it has fired, so it may already be gone here.
    try:
        as_.delete_scheduled_action(AutoScalingGroupName=name, ScheduledActionName=action_name)
    except Exception:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
