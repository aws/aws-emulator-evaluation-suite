"""delete-asg-removes-group."""
from __future__ import annotations

import re

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delete-asg-removes-group"
GROUP = 'group-lifecycle'
SERVICES = ['autoscaling']

#: The catalog-ami member's resolution: the same public parameter, the same GetParameter call.
_CATALOG_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


def _catalog_ami(ctx) -> str:
    """The AMI the catalog-ami member resolves; its absence is that prerequisite's failure."""
    from botocore.exceptions import ClientError

    try:
        return ctx.client("ssm").get_parameter(Name=_CATALOG_AMI_PARAM)["Parameter"]["Value"]
    except ClientError as exc:
        raise AssertionError(
            f"prerequisite catalog-ami: GetParameter({_CATALOG_AMI_PARAM}) failed: {exc}"
        ) from exc
#: Bounded convergence for the delete, sized from the default service-class budget.
_CONVERGE_WAIT_S = 240

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An empty group is created, updated and read back; DeleteAutoScalingGroup then makes it
    absent from describe results, from its tag-filtered listing, and unmutable."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")

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

    def _subnet_ids():
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        ).get("Subnets", [])
        if not subnets:
            raise AssertionError(
                "account baseline is missing its subnets of the run's shared network for Auto Scaling group placement"
            )
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
            LaunchTemplateData={"ImageId": _catalog_ami(ctx), "InstanceType": instance_type},
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
        ctx.on_cleanup(lambda n=asg_name: _delete_group_if_present(n))
        return asg_name

    def _delete_group_if_present(name):
        # The check deletes its own group; teardown only covers a run that stops before that.
        if _describe_group(name) is not None:
            as_.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)

    name = _make_asg(min_size=0, max_size=1, desired_capacity=0)
    created = _describe_group(name)
    assert created is not None, f"group {name} should be visible via DescribeAutoScalingGroups right after creation"
    arn = created.get("AutoScalingGroupARN") or ""
    arn_re = (
        rf"arn:aws:autoscaling:{re.escape(ctx.region)}:{re.escape(ctx.account)}:autoScalingGroup:"
        rf"[0-9a-f-]+:autoScalingGroupName/{re.escape(name)}"
    )
    assert re.fullmatch(arn_re, arn), f"expected AutoScalingGroupARN matching {arn_re!r}, got {arn!r}"

    # Use leg: an update is reflected on an independent read.
    as_.update_auto_scaling_group(AutoScalingGroupName=name, MaxSize=3, DefaultCooldown=120)
    updated = _describe_group(name)
    assert updated is not None and updated.get("MaxSize") == 3, (
        f"expected MaxSize 3 after UpdateAutoScalingGroup, got {updated and updated.get('MaxSize')!r}"
    )
    assert updated.get("DefaultCooldown") == 120, (
        f"expected DefaultCooldown 120 after UpdateAutoScalingGroup, got {updated.get('DefaultCooldown')!r}"
    )

    as_.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)

    # Beat 1: the by-name describe reports the miss in-band (the API has no read-by-name error).
    gone = _poll_until(
        lambda: _describe_group(name), lambda g: g is None, timeout_s=_CONVERGE_WAIT_S, interval_s=3,
        description="the deleted group to leave DescribeAutoScalingGroups",
    )
    assert gone is None, "group must no longer appear in DescribeAutoScalingGroups after delete"

    # Beat 2: the group is absent from the listing filtered to its own tag.
    tagged = [
        g.get("AutoScalingGroupName")
        for page in as_.get_paginator("describe_auto_scaling_groups").paginate(
            Filters=[{"Name": "tag:sim2real", "Values": [CHECK]}]
        )
        for g in page.get("AutoScalingGroups", [])
    ]
    assert name not in tagged, f"deleted group still listed under tag sim2real={CHECK}: {tagged!r}"

    # Beat 3: a mutation on the dead name is refused.
    try:
        as_.update_auto_scaling_group(AutoScalingGroupName=name, MaxSize=2)
        mutate_code, mutate_message, mutate_status = None, None, None
    except ClientError as exc:
        mutate_code = exc.response.get("Error", {}).get("Code")
        mutate_message = exc.response.get("Error", {}).get("Message")
        mutate_status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
    assert mutate_code == "ValidationError", (
        f"expected ValidationError mutating a deleted group {name}, got {mutate_code!r}"
    )
    assert isinstance(mutate_status, int) and 400 <= mutate_status < 500, f"expected HTTP 4xx mutating a deleted group, got {mutate_status!r}"
    expected_message = "AutoScalingGroup name not found - null"
    assert mutate_message == expected_message, f"expected the message {expected_message!r}, got {mutate_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
