"""percent-change-min-adjustment-magnitude."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "percent-change-min-adjustment-magnitude"
GROUP = 'scaling-policy'
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


def _error(fn):
    """Call fn(); return its ClientError (code, message). Raises on unexpected success."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PercentChangeInCapacity is floored by MinAdjustmentMagnitude (10% of 1 with floor 2: 1 -> 3),
    ExactCapacity sets capacity verbatim, and MinAdjustmentMagnitude with ChangeInCapacity is
    rejected with ValidationError."""
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
        # Drain capacity to zero before ForceDelete so no instance outlives the group.
        # A gone group is clean; an in-progress scaling activity is retried every 2 s for 60 s.
        deadline = time.monotonic() + 60.0
        while True:
            try:
                as_.update_auto_scaling_group(
                    AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0
                )
                break
            except ClientError as err:
                error = err.response["Error"]
                if error["Code"] == "ValidationError" and "not found" in error.get("Message", ""):
                    return
                if error["Code"] not in ("ScalingActivityInProgress", "ResourceContention") or (
                    time.monotonic() >= deadline
                ):
                    raise
            time.sleep(2)
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

    def _desired(name):
        g = _group(name)
        return g["DesiredCapacity"] if g else None

    def _ids_in_state(name, *states):
        g = _group(name)
        return sorted(
            i["InstanceId"]
            for i in (g.get("Instances", []) if g else [])
            if i.get("LifecycleState") in states
        )

    name = _make_asg(0, 4, 1)
    _poll(
        lambda: _ids_in_state(name, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=420,
        interval_s=10,
        description="setup: the group reached its initial capacity of 1 InService instance",
    )

    pct = ctx.unique_name("sim2real-behav-as-pct-")
    as_.put_scaling_policy(
        AutoScalingGroupName=name,
        PolicyName=pct,
        PolicyType="SimpleScaling",
        AdjustmentType="PercentChangeInCapacity",
        ScalingAdjustment=10,
        MinAdjustmentMagnitude=2,
        Cooldown=0,
    )
    stored = as_.describe_policies(AutoScalingGroupName=name, PolicyNames=[pct])["ScalingPolicies"]
    assert len(stored) == 1, f"expected one stored percent policy, got {stored}"
    assert stored[0]["AdjustmentType"] == "PercentChangeInCapacity", stored[0].get("AdjustmentType")
    assert stored[0]["ScalingAdjustment"] == 10, stored[0].get("ScalingAdjustment")
    assert stored[0]["MinAdjustmentMagnitude"] == 2, (
        f"MinAdjustmentMagnitude must round-trip, got {stored[0].get('MinAdjustmentMagnitude')!r}"
    )

    # 1. 10% of 1 instance is a sub-unit adjustment, so MinAdjustmentMagnitude=2 is the
    #    adjustment actually applied: DesiredCapacity 1 -> 3.
    as_.execute_policy(AutoScalingGroupName=name, PolicyName=pct, HonorCooldown=False)
    _poll(
        lambda: _desired(name),
        lambda d: d == 3,
        timeout_s=90,
        interval_s=3,
        description="MinAdjustmentMagnitude=2 floored the sub-unit percentage, lifting desired 1 -> 3",
    )
    assert _desired(name) == 3, (
        f"a 10% adjustment of 1 must be floored to MinAdjustmentMagnitude=2 (desired 1 -> 3), "
        f"got {_desired(name)}"
    )
    grown = _poll(
        lambda: _ids_in_state(name, "InService"),
        lambda ids: len(ids) == 3,
        timeout_s=420,
        interval_s=10,
        description="the floored percent adjustment actually launched 2 more instances",
    )
    assert len(grown) == 3, f"expected 3 InService instances, got {grown}"

    # 2. ExactCapacity ignores the current capacity and sets it verbatim -- and scale-in must
    #    really terminate the surplus, not just rewrite the field.
    exact = ctx.unique_name("sim2real-behav-as-exact-")
    as_.put_scaling_policy(
        AutoScalingGroupName=name,
        PolicyName=exact,
        PolicyType="SimpleScaling",
        AdjustmentType="ExactCapacity",
        ScalingAdjustment=1,
        Cooldown=0,
    )
    as_.execute_policy(AutoScalingGroupName=name, PolicyName=exact, HonorCooldown=False)
    _poll(
        lambda: _desired(name),
        lambda d: d == 1,
        timeout_s=90,
        interval_s=3,
        description="ExactCapacity=1 set DesiredCapacity to exactly 1 regardless of current capacity",
    )
    assert _desired(name) == 1, f"ExactCapacity=1 must set desired to 1, got {_desired(name)}"
    shrunk = _poll(
        lambda: _ids_in_state(name, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=420,
        interval_s=10,
        description="ExactCapacity=1 actually terminated the two surplus instances",
    )
    assert len(shrunk) == 1, f"expected exactly 1 surviving instance, got {shrunk}"
    assert set(shrunk) <= set(grown), f"scale-in must retain an existing instance, got {shrunk}"

    # MinAdjustmentMagnitude is only meaningful for PercentChangeInCapacity.
    # Pairing it with ChangeInCapacity must be refused, not stored as a dead field.
    bad = ctx.unique_name("sim2real-behav-as-badmag-")
    code, message = _error(
        lambda: as_.put_scaling_policy(
            AutoScalingGroupName=name,
            PolicyName=bad,
            PolicyType="SimpleScaling",
            AdjustmentType="ChangeInCapacity",
            ScalingAdjustment=1,
            MinAdjustmentMagnitude=2,
            Cooldown=0,
        )
    )
    assert code == "ValidationError", (
        f"MinAdjustmentMagnitude with AdjustmentType=ChangeInCapacity must raise ValidationError, "
        f"got {code!r}"
    )
    expected_message = "MinAdjustmentMagnitude is not supported by the specified adjustment type."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    names = {
        p["PolicyName"]
        for p in as_.describe_policies(AutoScalingGroupName=name)["ScalingPolicies"]
    }
    assert bad not in names, f"the rejected policy must not be stored; policies are {sorted(names)}"
    assert {pct, exact} <= names, f"the valid policies must survive; policies are {sorted(names)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
