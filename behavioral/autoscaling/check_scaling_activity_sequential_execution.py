"""scaling-activity-sequential-execution."""
from __future__ import annotations


from behavioral_harness import tags


CHECK = "scaling-activity-sequential-execution"
GROUP = 'ordering'
SERVICES = ['autoscaling']


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetDesiredCapacity then ExecutePolicy each record a scaling Activity, and
    DescribeScalingActivities lists them newest first, the ExecutePolicy one strictly later."""
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

    def _wait_for_in_service(name, count, timeout_s=420, interval_s=5):
        def _pred(ins):
            return (
                bool(ins)
                and len(ins) == count
                and all(i.get("LifecycleState") == "InService" for i in ins)
            )
        return _poll_until(lambda: _group_instances(name), _pred, timeout_s, interval_s)

    def _wait_for_capacity(name, predicate, timeout_s=60, interval_s=2):
        return _poll_until(lambda: _describe_group(name), predicate, timeout_s, interval_s)

    name = _make_asg(min_size=0, max_size=5, desired_capacity=0)
    policy_name = ctx.unique_name("sim2real-behav-as-pol-")
    as_.put_scaling_policy(
        AutoScalingGroupName=name,
        PolicyName=policy_name,
        PolicyType="SimpleScaling",
        AdjustmentType="ChangeInCapacity",
        ScalingAdjustment=1,
        Cooldown=0,
    )
    ctx.on_cleanup(lambda: as_.delete_policy(AutoScalingGroupName=name, PolicyName=policy_name))

    as_.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=1, HonorCooldown=False)
    _wait_for_capacity(name, lambda g: g is not None and g["DesiredCapacity"] == 1, timeout_s=60)
    _wait_for_in_service(name, 1, timeout_s=120)

    # Ensure the first activity is fully recorded as Successful (not merely in flight)
    # before triggering the second action, so the two are unambiguously separated in
    # time without resorting to an arbitrary sleep.
    _poll_until(
        lambda: as_.describe_scaling_activities(AutoScalingGroupName=name)["Activities"],
        lambda acts: any(a["StatusCode"] == "Successful" for a in acts),
        timeout_s=60,
        interval_s=2,
        description="the earlier SetDesiredCapacity scaling activity reaches Successful",
    )

    as_.execute_policy(AutoScalingGroupName=name, PolicyName=policy_name, HonorCooldown=False)
    _wait_for_capacity(name, lambda g: g is not None and g["DesiredCapacity"] == 2, timeout_s=60)

    activities = _poll_until(
        lambda: as_.describe_scaling_activities(AutoScalingGroupName=name)["Activities"],
        lambda acts: len(acts) >= 2,
        timeout_s=60,
        interval_s=2,
        description="at least 2 scaling activities recorded",
    )

    start_times = [a["StartTime"] for a in activities]
    assert start_times == sorted(start_times, reverse=True), (
        f"DescribeScalingActivities must return activities in reverse-chronological order, got {start_times}"
    )

    policy_acts = [a for a in activities if policy_name in a.get("Cause", "")]
    other_acts = [a for a in activities if policy_name not in a.get("Cause", "")]
    assert policy_acts, f"expected at least one activity caused by ExecutePolicy policy {policy_name!r}"
    assert other_acts, "expected at least one activity from the earlier SetDesiredCapacity call"
    assert min(a["StartTime"] for a in policy_acts) >= max(a["StartTime"] for a in other_acts), (
        "the ExecutePolicy-triggered activity must be recorded strictly after the earlier "
        "SetDesiredCapacity-triggered activity"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
