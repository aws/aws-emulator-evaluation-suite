"""capacity-bounds-converge-desired-capacity."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "capacity-bounds-converge-desired-capacity"
GROUP = 'capacity-management'
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
# ===== end helpers =====


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Changing MinSize/MaxSize moves DesiredCapacity to the new bound and the group converges
    its live InService instance count to it, launching up to a raised floor and terminating
    the surplus under a lowered ceiling."""
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
        # Billable-leak guard: an ASG deleted while it still holds capacity leaks EC2
        # instances. Drain min/max/desired to zero first, THEN ForceDelete so any straggler
        # is terminated by Auto Scaling itself.
        try:
            as_.update_auto_scaling_group(
                AutoScalingGroupName=name, MinSize=0, MaxSize=0, DesiredCapacity=0
            )
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ValidationError" and "not found" in err.get("Message", ""):
                return
            # A busy group refuses the drain; the ForceDelete below still removes it.
            if err["Code"] not in ("ScalingActivityInProgress", "ResourceContention"):
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

    name = _make_asg(0, 3, 0)
    initial = _group(name)
    assert initial["DesiredCapacity"] == 0, f"setup: DesiredCapacity should start at 0, got {initial['DesiredCapacity']}"
    assert initial["Instances"] == [], f"setup: group should start empty, got {initial['Instances']}"

    # 1. Raising MinSize above the current DesiredCapacity must raise DesiredCapacity to the
    #    new floor -- the group may never sit below its own minimum.
    as_.update_auto_scaling_group(AutoScalingGroupName=name, MinSize=2)
    raised = _poll(
        lambda: _group(name),
        lambda g: g is not None and g["DesiredCapacity"] == 2,
        timeout_s=90,
        interval_s=3,
        description="raising MinSize to 2 raised DesiredCapacity to the new floor",
    )
    assert raised["MinSize"] == 2, f"MinSize did not persist: {raised['MinSize']}"
    assert raised["DesiredCapacity"] == 2, (
        f"MinSize=2 must lift DesiredCapacity from 0 to 2, got {raised['DesiredCapacity']}"
    )

    # ...and the floor must be enforced by actually launching instances, not just stored.
    launched = _poll(
        lambda: _ids_in_state(name, "InService"),
        lambda ids: len(ids) == 2,
        timeout_s=420,
        interval_s=10,
        description="MinSize floor launched 2 instances to InService",
    )
    assert len(launched) == 2, f"expected 2 InService instances at the MinSize floor, got {launched}"

    # 2. Lowering MaxSize below the current DesiredCapacity must clamp DesiredCapacity down to
    #    the new ceiling and actually terminate the surplus instance.
    as_.update_auto_scaling_group(AutoScalingGroupName=name, MinSize=0, MaxSize=1)
    clamped = _poll(
        lambda: _group(name),
        lambda g: g is not None and g["DesiredCapacity"] == 1,
        timeout_s=90,
        interval_s=3,
        description="lowering MaxSize to 1 clamped DesiredCapacity to the new ceiling",
    )
    assert clamped["MaxSize"] == 1, f"MaxSize did not persist: {clamped['MaxSize']}"
    assert clamped["DesiredCapacity"] == 1, (
        f"MaxSize=1 must clamp DesiredCapacity from 2 to 1, got {clamped['DesiredCapacity']}"
    )

    survivors = _poll(
        lambda: _ids_in_state(name, "InService"),
        lambda ids: len(ids) == 1,
        timeout_s=420,
        interval_s=10,
        description="MaxSize ceiling terminated the surplus instance",
    )
    assert len(survivors) == 1, f"expected exactly 1 surviving instance, got {survivors}"
    assert set(survivors) <= set(launched), (
        f"scale-in must terminate one of the existing instances {launched}, not relaunch: {survivors}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
