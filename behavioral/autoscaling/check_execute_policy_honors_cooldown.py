"""execute-policy-honors-cooldown."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "execute-policy-honors-cooldown"
GROUP = 'scaling-policy'
SERVICES = ['autoscaling']


# ===== helpers =====
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


def _error(fn):
    """Run ``fn`` and return the botocore Error dict it raised. An unexpected success raises,
    so ignoring the cooldown is not reported as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")
# ===== end helpers =====


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Within a simple-scaling policy's Cooldown, ExecutePolicy with HonorCooldown=True is refused
    with ScalingActivityInProgress and leaves capacity unchanged, while HonorCooldown=False
    bypasses the cooldown and succeeds."""
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
        # Billable-leak guard: drain min/max/desired to zero, THEN ForceDelete.
        try:
            as_.update_auto_scaling_group(
                AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0
            )
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ValidationError":
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
    policy = ctx.unique_name("sim2real-behav-as-pol-")
    as_.put_scaling_policy(
        AutoScalingGroupName=name,
        PolicyName=policy,
        PolicyType="SimpleScaling",
        AdjustmentType="ChangeInCapacity",
        ScalingAdjustment=1,
        Cooldown=600,
    )
    stored = as_.describe_policies(AutoScalingGroupName=name, PolicyNames=[policy])[
        "ScalingPolicies"
    ]
    assert len(stored) == 1, f"expected exactly one stored policy, got {stored}"
    assert stored[0]["Cooldown"] == 600, (
        f"the policy's Cooldown must round-trip verbatim, got {stored[0].get('Cooldown')!r}"
    )
    assert stored[0]["PolicyType"] == "SimpleScaling", stored[0].get("PolicyType")

    # 1. A first policy-driven scale-out completes and starts the 600s cooldown clock.
    as_.execute_policy(AutoScalingGroupName=name, PolicyName=policy, HonorCooldown=False)
    _poll(
        ctx,
        lambda: _desired(name),
        lambda d: d == 1,
        timeout_s=90,
        interval_s=2,
        description="the first ExecutePolicy raised DesiredCapacity to 1",
    )
    first = _poll(
        ctx,
        lambda: _ids_in_state(name, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=420,
        interval_s=2,
        description="the first scaling activity reached a terminal InService state",
    )
    assert len(first) == 1, f"expected 1 InService instance after the first execution, got {first}"

    # 2. Inside the cooldown window an execution that HONORS the cooldown must be refused with
    #    the modeled ScalingActivityInProgress fault -- and capacity must not budge.
    error = _error(
        lambda: as_.execute_policy(
            AutoScalingGroupName=name, PolicyName=policy, HonorCooldown=True
        )
    )
    code = error.get("Code")
    assert code == "ScalingActivityInProgress", (
        f"ExecutePolicy(HonorCooldown=True) inside a 600s cooldown must raise "
        f"ScalingActivityInProgress, got {code!r}"
    )
    expected = "Scaling activity is in progress and blocks the execution of this policy"
    assert error.get("Message") == expected, f"expected message {expected!r}, got {error.get('Message')!r}"
    assert _desired(name) == 1, "a cooldown-blocked execution must leave DesiredCapacity at 1"
    assert _ids_in_state(name, "InService") == first, (
        f"a cooldown-blocked execution must not launch anything; fleet was {first}"
    )

    # 3. Control case: the identical call with HonorCooldown=False bypasses the cooldown.
    as_.execute_policy(AutoScalingGroupName=name, PolicyName=policy, HonorCooldown=False)
    _poll(
        ctx,
        lambda: _desired(name),
        lambda d: d == 2,
        timeout_s=90,
        interval_s=2,
        description="HonorCooldown=False bypassed the cooldown and raised DesiredCapacity to 2",
    )
    grown = _poll(
        ctx,
        lambda: _ids_in_state(name, "InService"),
        lambda ids: len(ids) == 2,
        timeout_s=420,
        interval_s=2,
        description="the cooldown-bypassing execution actually launched a second instance",
    )
    assert len(grown) == 2, f"control case expected 2 InService instances, got {grown}"

    # Absence by contrast: read after the control's launch, the refused call added no capacity.
    desired = _desired(name)
    assert desired == 2, (
        f"after one refused and one bypassing execution DesiredCapacity must be 2, got {desired!r}"
    )
    launches = [
        a for a in as_.describe_scaling_activities(AutoScalingGroupName=name)["Activities"]
        if a.get("Description", "").startswith("Launching a new EC2 instance")
        and a.get("StatusCode") == "Successful"
    ]
    assert len(launches) == 2, (
        f"the group must record exactly two successful launches, one per accepted execution: "
        f"{[a.get('Description') for a in launches]}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
