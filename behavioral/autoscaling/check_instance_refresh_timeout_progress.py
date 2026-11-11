"""instance-refresh-timeout-progress."""
from __future__ import annotations

from datetime import datetime, timezone


from behavioral_harness import tags


CHECK = "instance-refresh-timeout-progress"
GROUP = 'visibility-timeout-ttl'
SERVICES = ['autoscaling']


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A running instance refresh reports PercentageComplete/StartTime that are internally
    consistent with real elapsed time: percentage never regresses while InProgress, and
    the reported StartTime is a plausible short interval in the past."""
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

    def _refresh(name, refresh_id):
        resp = as_.describe_instance_refreshes(
            AutoScalingGroupName=name, InstanceRefreshIds=[refresh_id]
        )
        return resp["InstanceRefreshes"][0]

    name = _make_asg(min_size=0, max_size=3, desired_capacity=2)
    _wait_for_in_service(name, 2, timeout_s=420, interval_s=5)

    start_resp = as_.start_instance_refresh(
        AutoScalingGroupName=name,
        Preferences={"MinHealthyPercentage": 50, "InstanceWarmup": 30},
    )
    refresh_id = start_resp["InstanceRefreshId"]

    first = _poll_until(
        lambda: _refresh(name, refresh_id),
        lambda r: r.get("StartTime") is not None,
        timeout_s=30,
        interval_s=1,
        description=f"refresh {refresh_id} reports a StartTime",
    )
    assert isinstance(first.get("PercentageComplete"), int), (
        f"expected PercentageComplete to be an int once StartTime is reported, "
        f"got {first.get('PercentageComplete')!r}"
    )
    assert 0 <= first["PercentageComplete"] <= 100, (
        f"expected PercentageComplete in [0, 100], got {first['PercentageComplete']}"
    )
    now = datetime.now(timezone.utc)
    elapsed = (now - first["StartTime"]).total_seconds()
    # Small negative slack tolerates clock skew between the local clock and AWS's
    # server-side StartTime timestamp; the key claim is "recent", not "in the past to
    # the millisecond".
    assert -5 <= elapsed < 120, f"elapsed time since reported StartTime is implausible: {elapsed}s"

    # Sample progress repeatedly over a real time window (instead of a single
    # sleep-then-check) so a regression at ANY point along the way is caught.
    samples = [first]

    def _sample():
        r = _refresh(name, refresh_id)
        samples.append(r)
        return r

    _poll_until(
        _sample,
        lambda r: len(samples) >= 6,
        timeout_s=60,
        interval_s=3,
        description="collect refresh progress samples over ~15s of real elapsed time",
    )
    second = samples[-1]
    assert second["Status"] in ("InProgress", "Successful", "Cancelling", "Cancelled"), (
        f"expected Status to be one of InProgress/Successful/Cancelling/Cancelled "
        f"after {len(samples)} samples, got {second['Status']!r}"
    )
    percentages = [s["PercentageComplete"] for s in samples]
    assert percentages == sorted(percentages), (
        f"PercentageComplete must never regress while a refresh is in progress: {percentages}"
    )

    # Clean up: cancel so the refresh doesn't linger past this check's lifetime.
    try:
        as_.cancel_instance_refresh(AutoScalingGroupName=name)
    except Exception:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
