"""step-scaling-selects-matching-step-adjustment."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "step-scaling-selects-matching-step-adjustment"
GROUP = 'scaling-policy'
SERVICES = ['autoscaling']


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll(fn, pred, *, timeout_s, interval_s=2, description="condition", ctx=None):
    """Poll ``fn`` until ``pred`` holds; raise with the last observed value on timeout."""
    deadline = time.monotonic() + timeout_s
    last = fn()
    while not pred(last):
        if time.monotonic() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{description}: the run budget ended first; not graded")
            raise AssertionError(f"{description} not met within {timeout_s}s; last={last!r}")
        time.sleep(interval_s)
        last = fn()
    return last


def _holds_for(fn, pred, *, seconds, interval_s=2, description="condition"):
    """Assert ``pred`` holds continuously for ``seconds`` -- proves an effect stayed ABSENT."""
    deadline = time.monotonic() + seconds
    while True:
        val = fn()
        if not pred(val):
            raise AssertionError(f"{description} stopped holding; observed {val!r}")
        if time.monotonic() >= deadline:
            return val
        time.sleep(interval_s)


def _error(fn):
    """Run ``fn``, returning the ClientError (code, message) it raised; raises on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A StepScaling policy applies the ScalingAdjustment of the step whose interval contains
    (MetricValue - BreachThreshold); executing it without them is rejected and moves no capacity."""
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

    name = _make_asg(0, 3, 0)
    policy = ctx.unique_name("sim2real-behav-as-step-")
    as_.put_scaling_policy(
        AutoScalingGroupName=name,
        PolicyName=policy,
        PolicyType="StepScaling",
        AdjustmentType="ChangeInCapacity",
        MetricAggregationType="Average",
        EstimatedInstanceWarmup=0,
        StepAdjustments=[
            {
                "MetricIntervalLowerBound": 0.0,
                "MetricIntervalUpperBound": 10.0,
                "ScalingAdjustment": 1,
            },
            {"MetricIntervalLowerBound": 10.0, "ScalingAdjustment": 2},
        ],
    )

    stored = as_.describe_policies(AutoScalingGroupName=name, PolicyNames=[policy])[
        "ScalingPolicies"
    ]
    assert len(stored) == 1, f"expected exactly one stored policy, got {stored}"
    pol = stored[0]
    assert pol["PolicyType"] == "StepScaling", pol.get("PolicyType")
    assert pol["MetricAggregationType"] == "Average", (
        f"MetricAggregationType must round-trip, got {pol.get('MetricAggregationType')!r}"
    )
    steps = sorted(pol["StepAdjustments"], key=lambda s: s.get("MetricIntervalLowerBound", 0.0))
    assert len(steps) == 2, f"both step adjustments must be stored, got {steps}"
    assert steps[0]["MetricIntervalLowerBound"] == 0.0, steps[0]
    assert steps[0]["MetricIntervalUpperBound"] == 10.0, steps[0]
    assert steps[0]["ScalingAdjustment"] == 1, steps[0]
    assert steps[1]["MetricIntervalLowerBound"] == 10.0, steps[1]
    assert steps[1]["ScalingAdjustment"] == 2, steps[1]
    # The open-ended final step must have NO upper bound; a fabricated one would make the top
    # step unreachable.
    assert "MetricIntervalUpperBound" not in steps[1], (
        f"the unbounded final step must not gain an upper bound: {steps[1]}"
    )

    # 1. MetricValue 55 against BreachThreshold 50 is an offset of +5, inside [0, 10) --
    #    the FIRST step applies: +1.
    as_.execute_policy(
        AutoScalingGroupName=name,
        PolicyName=policy,
        MetricValue=55.0,
        BreachThreshold=50.0,
        HonorCooldown=False,
    )
    _poll(
        lambda: _desired(name),
        lambda d: d == 1,
        timeout_s=_budget_s(ctx, 90),
        interval_s=2,
        description="a +5 metric offset selected the [0,10) step and added exactly 1",
        ctx=ctx,
    )
    assert _desired(name) == 1, (
        f"a +5 offset must select the [0,10) step (+1), not another step; desired={_desired(name)}"
    )
    _poll(
        lambda: _ids_in_state(name, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=_budget_s(ctx, 420),
        interval_s=2,
        description="the first step's adjustment actually launched 1 instance",
        ctx=ctx,
    )

    # 2. MetricValue 75 against BreachThreshold 50 is an offset of +25, in [10, inf) --
    #    the SECOND step applies: +2, taking desired from 1 to 3 (not to 2).
    as_.execute_policy(
        AutoScalingGroupName=name,
        PolicyName=policy,
        MetricValue=75.0,
        BreachThreshold=50.0,
        HonorCooldown=False,
    )
    _poll(
        lambda: _desired(name),
        lambda d: d == 3,
        timeout_s=_budget_s(ctx, 90),
        interval_s=2,
        description="a +25 metric offset selected the [10,inf) step and added exactly 2",
        ctx=ctx,
    )
    assert _desired(name) == 3, (
        f"a +25 offset must select the unbounded step (+2) from desired=1, got {_desired(name)}"
    )
    live = _poll(
        lambda: _ids_in_state(name, "InService"),
        lambda ids: len(ids) == 3,
        timeout_s=_budget_s(ctx, 420),
        interval_s=2,
        description="the second step's adjustment actually launched 2 more instances",
        ctx=ctx,
    )
    assert len(live) == 3, f"expected 3 InService instances after the second step, got {live}"

    # A step-scaling policy cannot be executed without a metric value and breach threshold:
    # there is no step to select, so capacity must not move.
    code, message = _error(
        lambda: as_.execute_policy(
            AutoScalingGroupName=name, PolicyName=policy, HonorCooldown=False
        )
    )
    assert code == "ValidationError", (
        f"ExecutePolicy on a StepScaling policy without MetricValue/BreachThreshold must raise "
        f"ValidationError, got {code!r}"
    )
    assert message == "Metric value must be specified for policy type StepScaling", (
        f"unexpected ValidationError message: {message!r}"
    )
    _holds_for(
        lambda: _desired(name),
        lambda d: d == 3,
        seconds=10,
        interval_s=2,
        description="the rejected step execution must leave DesiredCapacity at 3",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
