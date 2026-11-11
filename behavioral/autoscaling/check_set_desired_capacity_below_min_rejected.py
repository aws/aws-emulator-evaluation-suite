"""set-desired-capacity-below-min-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "set-desired-capacity-below-min-rejected"
GROUP = 'overly-permissive'
SERVICES = ['autoscaling']


# ===== helpers =====
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


def _holds_for(fn, pred, *, seconds, interval_s=5, description="condition"):
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
    """Run ``fn``, returning the ClientError (code, message) it raised. An unexpected success raises: the call must be refused."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")
# ===== end helpers =====


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetDesiredCapacity and UpdateAutoScalingGroup both reject a desired capacity below MinSize
    rather than clamp or accept it, so no instance the minimum protects is scaled in."""
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

    def _ids_in_state(name, *states):
        g = _group(name)
        return sorted(
            i["InstanceId"]
            for i in (g.get("Instances", []) if g else [])
            if i.get("LifecycleState") in states
        )

    # Full valid setup: a group holding exactly its minimum of one live instance.
    name = _make_asg(1, 3, 1)
    running = _poll(
        lambda: _ids_in_state(name, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=420,
        interval_s=10,
        description="setup: the group reached its MinSize of 1 InService instance",
    )
    assert len(running) == 1, f"setup expected 1 InService instance, got {running}"

    # Break exactly one thing: ask for a desired capacity under the group's own minimum.
    code, message = _error(
        lambda: as_.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=0)
    )
    assert code == "ValidationError", (
        f"SetDesiredCapacity(0) below MinSize=1 must raise ValidationError, got {code!r}"
    )
    assert message == (
        "New SetDesiredCapacity value 0 is below min value 1 for the AutoScalingGroup."
    ), f"unexpected SetDesiredCapacity ValidationError message: {message!r}"

    # Effect absent: neither the record nor the live fleet may move.
    after = _group(name)
    assert after["DesiredCapacity"] == 1, (
        f"a rejected SetDesiredCapacity must not change DesiredCapacity, got {after['DesiredCapacity']}"
    )
    assert after["MinSize"] == 1, f"MinSize must be untouched, got {after['MinSize']}"
    _holds_for(
        lambda: _ids_in_state(name, "InService"),
        lambda ids: ids == running,
        seconds=45,
        interval_s=10,
        description=f"the rejected scale-in must not terminate {running}",
    )

    # The UpdateAutoScalingGroup path is a separate code path and must reject the same way,
    # leaving MinSize intact rather than silently lowering it to fit.
    code2, message2 = _error(
        lambda: as_.update_auto_scaling_group(AutoScalingGroupName=name, DesiredCapacity=0)
    )
    assert code2 == "ValidationError", (
        f"UpdateAutoScalingGroup(DesiredCapacity=0) below MinSize=1 must raise ValidationError, got {code2!r}"
    )
    assert message2 == "Desired capacity:0 must be between the specified min size:1 and max size:3", (
        f"unexpected UpdateAutoScalingGroup ValidationError message: {message2!r}"
    )
    after2 = _group(name)
    assert after2["DesiredCapacity"] == 1 and after2["MinSize"] == 1, (
        f"rejected update must leave capacity bounds intact, got min={after2['MinSize']} "
        f"desired={after2['DesiredCapacity']}"
    )

    # Control case: an in-bounds request on the very same group still works end to end.
    as_.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=2)
    grown = _poll(
        lambda: _ids_in_state(name, "InService"),
        lambda ids: len(ids) == 2,
        timeout_s=420,
        interval_s=10,
        description="control case: an in-bounds SetDesiredCapacity(2) launched a second instance",
    )
    assert len(grown) == 2, f"control case expected 2 InService instances, got {grown}"
    assert set(running) <= set(grown), (
        f"scale-out must keep the original instance {running}, got {grown}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
