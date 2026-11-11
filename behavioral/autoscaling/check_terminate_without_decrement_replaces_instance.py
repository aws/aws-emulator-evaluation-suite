"""terminate-without-decrement-replaces-instance."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "terminate-without-decrement-replaces-instance"
GROUP = 'capacity-management'
SERVICES = ['autoscaling']

_TERMINAL_ACTIVITY_STATUSES = ("Successful", "Failed", "Cancelled")


def _poll(ctx, fn, pred, *, timeout_s, interval_s=2, description="condition"):
    """Poll ``fn`` until ``pred`` holds; raise with the last observed value on timeout."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    last = fn()
    while not pred(last):
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)
        last = fn()
    return last


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TerminateInstanceInAutoScalingGroup with ShouldDecrementDesiredCapacity=False leaves
    DesiredCapacity untouched and the group launches a REPLACEMENT, recorded as its own scaling
    activity after the termination activity."""
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
        # Drain capacity to zero before ForceDelete so no instance outlives the group; a
        # scaling activity already in flight is harmless since ForceDelete removes the
        # instances anyway, but any other failure here must still surface.
        try:
            as_.update_auto_scaling_group(
                AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ScalingActivityInProgressFault":
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

    def _ids_in_state(name, *states):
        g = _group(name)
        return sorted(
            i["InstanceId"]
            for i in (g.get("Instances", []) if g else [])
            if i.get("LifecycleState") in states
        )

    def _activities(name):
        return as_.describe_scaling_activities(AutoScalingGroupName=name).get("Activities", [])

    def _activities_mentioning(name, instance_id):
        return [
            a
            for a in _activities(name)
            if instance_id in f"{a.get('Description', '')} {a.get('Cause', '')}"
        ]

    name = _make_asg(1, 2, 1)
    original = _poll(
        ctx,
        lambda: _ids_in_state(name, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=420,
        description="setup: the group reached 1 InService instance",
    )[0]

    resp = as_.terminate_instance_in_auto_scaling_group(
        InstanceId=original, ShouldDecrementDesiredCapacity=False
    )
    activity = resp["Activity"]
    assert activity["ActivityId"], f"the termination must return an ActivityId, got {activity}"
    assert activity["AutoScalingGroupName"] == name, (
        f"the returned activity must belong to {name}, got {activity.get('AutoScalingGroupName')!r}"
    )
    assert activity.get("Description") == f"Terminating EC2 instance: {original}", (
        f"the returned activity must describe terminating {original}, got {activity.get('Description')!r}"
    )

    # DesiredCapacity must not move: that is the meaning of ShouldDecrementDesiredCapacity=False.
    desired = _group(name)["DesiredCapacity"]
    assert desired == 1, (
        f"ShouldDecrementDesiredCapacity=False must leave DesiredCapacity at 1, got {desired!r}"
    )

    # Convergence: the group launches a different instance to get back to DesiredCapacity.
    replacement = _poll(
        ctx,
        lambda: (
            [i["InstanceId"] for i in (_group(name) or {}).get("Instances", [])],
            _ids_in_state(name, "InService"),
        ),
        lambda pair: original not in pair[0] and len(pair[1]) == 1 and pair[1][0] != original,
        timeout_s=900,
        description=f"the group replaced the terminated {original} with a new InService instance",
    )[1][0]
    assert replacement != original, f"the replacement must be a new instance id, got {replacement}"

    g = _group(name)
    assert g["DesiredCapacity"] == 1, (
        f"DesiredCapacity must still be 1 after the replacement, got {g['DesiredCapacity']}"
    )

    # Both halves must be recorded as scaling activities, the launch after the termination.
    term_acts = _activities_mentioning(name, original)
    assert term_acts, (
        f"DescribeScalingActivities must record the termination of {original}; activities were "
        f"{[a.get('Description') for a in _activities(name)]}"
    )
    assert any(a["StatusCode"] in _TERMINAL_ACTIVITY_STATUSES for a in term_acts), (
        f"the termination activity must reach a terminal StatusCode, got "
        f"{[a['StatusCode'] for a in term_acts]}"
    )
    launch_acts = _activities_mentioning(name, replacement)
    assert launch_acts, (
        f"DescribeScalingActivities must record the launch of the replacement {replacement}; "
        f"activities were {[a.get('Description') for a in _activities(name)]}"
    )
    assert min(a["StartTime"] for a in launch_acts) >= min(
        a["StartTime"] for a in term_acts
    ), "the replacement launch activity must start no earlier than the termination activity"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
