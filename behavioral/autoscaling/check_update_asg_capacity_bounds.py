"""update-asg-capacity-bounds."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "update-asg-capacity-bounds"
GROUP = 'capacity-management'
SERVICES = ['autoscaling']


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateAutoScalingGroup persists new Min/Max/Desired capacity values (positive control),
    and a DesiredCapacity that exceeds the group's MaxSize in the very same call is rejected with
    the existing sizing left completely unchanged."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    def _image_id():
        param = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        try:
            return ssm.get_parameter(Name=param)["Parameter"]["Value"]
        except Exception:
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
        ctx.on_cleanup(
            lambda n=asg_name: as_.delete_auto_scaling_group(
                AutoScalingGroupName=n, ForceDelete=True
            )
        )
        return asg_name

    name = _make_asg(min_size=0, max_size=2, desired_capacity=0)

    # Positive control: a legitimate capacity change is applied in place and read back through
    # an independent DescribeAutoScalingGroups call.
    as_.update_auto_scaling_group(AutoScalingGroupName=name, MinSize=1, MaxSize=5, DesiredCapacity=3)

    group = _describe_group(name)
    assert group["MinSize"] == 1, f"MinSize did not persist: {group['MinSize']}"
    assert group["MaxSize"] == 5, f"MaxSize did not persist: {group['MaxSize']}"
    assert group["DesiredCapacity"] == 3, f"DesiredCapacity did not persist: {group['DesiredCapacity']}"

    # Bounds enforcement: a DesiredCapacity that exceeds the group's current MaxSize (5), asked
    # for in the same call and with no corresponding MaxSize raise, must be rejected outright --
    # not silently clamped to the ceiling and not merged with the existing MaxSize.
    code, message = _error(
        lambda: as_.update_auto_scaling_group(AutoScalingGroupName=name, DesiredCapacity=10)
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    assert message == "Desired capacity:10 must be between the specified min size:1 and max size:5", (
        f"unexpected ValidationError message: {message!r}"
    )

    unchanged = _describe_group(name)
    assert unchanged["MinSize"] == 1, f"rejected update changed MinSize: {unchanged['MinSize']}"
    assert unchanged["MaxSize"] == 5, f"rejected update changed MaxSize: {unchanged['MaxSize']}"
    assert unchanged["DesiredCapacity"] == 3, (
        f"rejected update changed DesiredCapacity: {unchanged['DesiredCapacity']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
