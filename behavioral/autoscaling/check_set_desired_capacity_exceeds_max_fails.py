"""set-desired-capacity-exceeds-max-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "set-desired-capacity-exceeds-max-fails"
GROUP = 'overly-permissive'
SERVICES = ['autoscaling']

_MANAGED_TAGS = {"sim2real": "as-depth", "sim2real:managed": "true"}


def _tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _MANAGED_TAGS.items()]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SetDesiredCapacity above MaxSize is rejected rather than clamped or accepted, while an in-bounds
    SetDesiredCapacity on the same group succeeds."""
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
            TagSpecifications=[{"ResourceType": "launch-template", "Tags": _tags_kv()}],
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
            "Tags": [
                {"Key": k, "Value": v, "PropagateAtLaunch": True}
                for k, v in _MANAGED_TAGS.items()
            ],
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

    # Positive control: an in-bounds SetDesiredCapacity on this same group must be accepted and
    # actually change the group's recorded DesiredCapacity.
    as_.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=1)
    group = _describe_group(name)
    assert group["DesiredCapacity"] == 1, (
        f"a legal SetDesiredCapacity within [MinSize, MaxSize] was not applied: "
        f"{group['DesiredCapacity']!r}"
    )

    # Break exactly one thing: ask for 5 in a group whose MaxSize is 2.
    try:
        result = as_.set_desired_capacity(AutoScalingGroupName=name, DesiredCapacity=5)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(
            f"SetDesiredCapacity(5) above MaxSize=2 SUCCEEDED and returned {result!r}"
        )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    assert message == (
        "New SetDesiredCapacity value 5 is above max value 2 for the AutoScalingGroup."
    ), f"unexpected ValidationError message: {message!r}"

    group = _describe_group(name)
    assert group["DesiredCapacity"] == 1, (
        f"rejected SetDesiredCapacity must not mutate the group: expected DesiredCapacity 1, "
        f"got {group['DesiredCapacity']!r}"
    )
    assert len(group["Instances"]) <= 1, (
        f"rejected SetDesiredCapacity must not launch beyond the last accepted desired "
        f"capacity (1): got {len(group['Instances'])} instances"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
