"""create-asg-state-transition."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags


CHECK = "create-asg-state-transition"
GROUP = 'group-lifecycle'
SERVICES = ['autoscaling']

DATAPLANE_MARKER = "DATAPLANE_UNIMPLEMENTED"


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
    """A group created with DesiredCapacity=1 drives its own instance to InService with no further
    capacity call, recorded as a Successful launch activity naming that instance: the capacity is
    acted on, not just stored."""
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

    def _describe_group(name):
        groups = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[name]).get(
            "AutoScalingGroups", []
        )
        return groups[0] if groups else None

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
        ctx.on_cleanup(lambda n=asg_name: _teardown_asg(n))
        return asg_name

    name = _make_asg(min_size=0, max_size=2, desired_capacity=1)

    group = _describe_group(name)
    assert group is not None, "newly created group must be describable"
    assert group["MinSize"] == 0
    assert group["MaxSize"] == 2
    assert group["DesiredCapacity"] == 1
    assert group["AutoScalingGroupARN"], "group must have an ARN"
    # Server-side defaults must be materialized, not omitted.
    assert group["HealthCheckType"] == "EC2", f"default HealthCheckType must be EC2, got {group.get('HealthCheckType')}"
    assert group["DefaultCooldown"] == 300, f"default cooldown must be 300s, got {group.get('DefaultCooldown')}"
    assert group["SuspendedProcesses"] == []
    assert "CreatedTime" in group, "group must expose CreatedTime"

    try:
        settled = _poll(
            lambda: _describe_group(name),
            lambda g: g is not None
            and len(g.get("Instances", [])) == 1
            and g["Instances"][0]["LifecycleState"] == "InService",
            timeout_s=420,
            interval_s=10,
            description="the instance launched by CreateAutoScalingGroup's own DesiredCapacity to reach InService",
        )
    except AssertionError as exc:
        # Whether an instance launches is decided by the EC2/Auto Scaling engine, not by the API
        # that accepted CreateAutoScalingGroup; the marker names a group that never launched one.
        raise AssertionError(f"{DATAPLANE_MARKER}: {exc}") from exc
    assert settled["Instances"][0]["LifecycleState"] == "InService"
    assert settled["DesiredCapacity"] == 1

    # The launch is acted on, not just stored: the group's activity history names the instance
    # it launched, and that activity settles Successful.
    instance_id = settled["Instances"][0]["InstanceId"]
    launch = _poll(
        lambda: [
            a for a in as_.describe_scaling_activities(AutoScalingGroupName=name).get("Activities", [])
            if instance_id in a.get("Description", "")
        ],
        lambda acts: any(a["StatusCode"] in ("Successful", "Failed", "Cancelled") for a in acts),
        timeout_s=180,
        interval_s=3,
        description=f"the scaling activity launching {instance_id} to settle",
    )
    codes = [a["StatusCode"] for a in launch]
    assert "Successful" in codes, f"expected the launch activity for {instance_id} to succeed, got {launch}"
    assert any(a["Description"].startswith("Launching a new EC2 instance") for a in launch), (
        f"expected a launch activity naming {instance_id}, got {launch}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
