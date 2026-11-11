"""termination-policy-selects-instance."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "termination-policy-selects-instance"
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
    """Run ``fn``, returning the ClientError (code, message) it raised; an unexpected success raises,
    so an over-permissive target reads as the acceptance it is, not as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TerminationPolicies decides which instance dies on scale-in: OldestInstance terminates the
    first-launched instance and NewestInstance the last-launched one (instances launch one at a
    time so oldest and newest are unambiguous)."""
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
        # A single subnet keeps AZ balancing out of the termination decision, so the only
        # discriminator left is the configured termination policy.
        return [sorted(subnets, key=lambda s: s["AvailabilityZone"])[0]["SubnetId"]]

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
        # Drain min/max/desired to zero, then ForceDelete; a busy group is retried for 60 s.
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

    def _in_service(name):
        g = _group(name)
        return sorted(
            i["InstanceId"]
            for i in (g.get("Instances", []) if g else [])
            if i.get("LifecycleState") == "InService"
        )

    def _scale_to(name, desired, count, description):
        as_.set_desired_capacity(
            AutoScalingGroupName=name, DesiredCapacity=desired, HonorCooldown=False
        )
        return _poll(
            lambda: _in_service(name),
            lambda ids: len(ids) == count,
            timeout_s=900,
            interval_s=15,
            description=description,
        )

    name = _make_asg(0, 2, 0, TerminationPolicies=["OldestInstance"], DefaultCooldown=0)
    assert _group(name)["TerminationPolicies"] == ["OldestInstance"], (
        f"TerminationPolicies must round-trip, got {_group(name)['TerminationPolicies']}"
    )

    # Launch instance A, then instance B, sequentially: A is strictly the oldest.
    first = _scale_to(name, 1, 1, "the first instance (A) reached InService")[0]
    both = _scale_to(name, 2, 2, "the second instance (B) reached InService alongside A")
    second = next(i for i in both if i != first)

    # 1. OldestInstance must terminate A and keep B.
    survivors = _scale_to(name, 1, 1, "scale-in to 1 left exactly one InService instance")
    assert survivors == [second], (
        f"TerminationPolicies=['OldestInstance'] must terminate the oldest instance {first} and "
        f"keep {second}; survivors were {survivors}"
    )

    # 2. Flip the policy: NewestInstance must now terminate the most recently launched instance.
    as_.update_auto_scaling_group(
        AutoScalingGroupName=name, TerminationPolicies=["NewestInstance"]
    )
    assert _group(name)["TerminationPolicies"] == ["NewestInstance"], (
        f"the updated TerminationPolicies must persist, got {_group(name)['TerminationPolicies']}"
    )
    pair = _scale_to(name, 2, 2, "a third instance (C) reached InService alongside B")
    third = next(i for i in pair if i != second)
    survivors2 = _scale_to(name, 1, 1, "scale-in to 1 under NewestInstance left one instance")
    assert survivors2 == [second], (
        f"TerminationPolicies=['NewestInstance'] must terminate the newest instance {third} and "
        f"keep {second}; survivors were {survivors2}"
    )

    # Rejection half: an unknown termination policy must be refused outright, leaving the
    # configured policy intact rather than storing a name the engine cannot honour.
    code, message = _error(
        lambda: as_.update_auto_scaling_group(
            AutoScalingGroupName=name, TerminationPolicies=["NotARealPolicy"]
        )
    )
    assert code == "ValidationError", (
        f"an unknown termination policy must raise ValidationError, got {code!r}"
    )
    assert message == (
        "[NotARealPolicy] is not a valid termination policy. Valid termination policies are: "
        "[AllocationStrategy, ClosestToNextInstanceHour, Default, Lambda, NewestInstance, "
        "OldestInstance, OldestLaunchConfiguration, OldestLaunchTemplate]."
    ), f"unexpected ValidationError message: {message!r}"
    assert _group(name)["TerminationPolicies"] == ["NewestInstance"], (
        f"the rejected update must leave TerminationPolicies at ['NewestInstance'], got "
        f"{_group(name)['TerminationPolicies']}"
    )
    assert _in_service(name) == [second], (
        f"the rejected update must not disturb the fleet; expected [{second}], got {_in_service(name)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
