"""unhealthy-instance-replaced."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "unhealthy-instance-replaced"
GROUP = 'instance-lifecycle'
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
    """Run ``fn``; return the ClientError (code, message) it raised. An unexpected success raises:
    it means the target accepts what AWS refuses, which is not a mere code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Marking an instance Unhealthy makes Auto Scaling terminate it and launch a replacement
    that holds DesiredCapacity: the self-healing loop, not just the recorded health flag."""
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
        # Drain min/max/desired to zero, then ForceDelete: this group has a non-zero MinSize.
        # A busy group is retried for 60 s; a missing one is already gone.
        deadline = time.monotonic() + 60
        while True:
            try:
                as_.update_auto_scaling_group(
                    AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0
                )
                break
            except ClientError as exc:
                err = exc.response["Error"]
                if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
                    return
                if err["Code"] not in ("ScalingActivityInProgress", "ResourceContention") or (
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
            "HealthCheckType": "EC2",
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

    def _ids_in_state(name, *states):
        return sorted(
            i["InstanceId"] for i in _instances(name) if i.get("LifecycleState") in states
        )

    def _health(name, instance_id):
        for inst in _instances(name):
            if inst["InstanceId"] == instance_id:
                return inst.get("HealthStatus")
        return None

    name = _make_asg(1, 2, 1)
    original = _poll(
        lambda: _ids_in_state(name, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=420,
        interval_s=10,
        description="setup: the group reached 1 InService instance",
    )[0]
    assert _health(name, original) == "Healthy", (
        f"setup: {original} should start Healthy, got {_health(name, original)!r}"
    )

    # Break exactly one thing: declare the only instance unhealthy, skipping the grace period so
    # the health-check remediation fires immediately.
    as_.set_instance_health(
        InstanceId=original, HealthStatus="Unhealthy", ShouldRespectGracePeriod=False
    )
    assert _health(name, original) == "Unhealthy", (
        f"SetInstanceHealth must flip HealthStatus, got {_health(name, original)!r}"
    )

    # The remediation loop: the unhealthy instance is removed AND a different instance is
    # launched into InService to hold DesiredCapacity.
    replacement = _poll(
        lambda: (
            [i["InstanceId"] for i in _instances(name)],
            _ids_in_state(name, "InService"),
        ),
        lambda pair: original not in pair[0] and len(pair[1]) == 1 and pair[1][0] != original,
        timeout_s=900,
        interval_s=15,
        description=(
            f"the unhealthy instance {original} was terminated and a replacement reached InService"
        ),
    )[1][0]
    assert replacement != original, (
        f"the replacement must be a new instance, not the unhealthy {original}"
    )
    assert _health(name, replacement) == "Healthy", (
        f"the replacement must be Healthy, got {_health(name, replacement)!r}"
    )

    # The group must have held its capacity contract, not quietly shrunk to accommodate a failure.
    g = _group(name)
    assert g["DesiredCapacity"] == 1, (
        f"health-check replacement must not change DesiredCapacity, got {g['DesiredCapacity']}"
    )
    assert g["MinSize"] == 1, f"MinSize must be untouched, got {g['MinSize']}"

    # Negative half: SetInstanceHealth must reject a status outside the enum, leaving health alone.
    code, message = _error(
        lambda: as_.set_instance_health(InstanceId=replacement, HealthStatus="Sick")
    )
    assert code == "ValidationError", (
        f"SetInstanceHealth with a status outside {{Healthy, Unhealthy}} must raise "
        f"ValidationError, got {code!r}"
    )
    assert message == "Valid instance health states are: [Healthy, Unhealthy].", (
        f"unexpected ValidationError message: {message!r}"
    )
    assert _health(name, replacement) == "Healthy", (
        f"a rejected SetInstanceHealth must leave HealthStatus Healthy, got "
        f"{_health(name, replacement)!r}"
    )

    # ...and must reject an instance that is not a member of any Auto Scaling group.
    code2, message2 = _error(
        lambda: as_.set_instance_health(
            InstanceId="i-0123456789abcdef0", HealthStatus="Unhealthy"
        )
    )
    assert code2 == "ValidationError", (
        f"SetInstanceHealth on a non-member instance must raise ValidationError, got {code2!r}"
    )
    assert message2 == "Instance Id not found - Instance i-0123456789abcdef0 not found", (
        f"unexpected ValidationError message: {message2!r}"
    )
    assert _ids_in_state(name, "InService") == [replacement], (
        f"the rejected calls must not disturb the fleet; expected [{replacement}], got "
        f"{_ids_in_state(name, 'InService')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
