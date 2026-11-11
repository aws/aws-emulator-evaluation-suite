"""update-nonexistent-group-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "update-nonexistent-group-fails"
GROUP = 'error-semantics'
SERVICES = ['autoscaling']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateAutoScalingGroup on an unknown group raises ValidationError instead of creating it, while
    the same call shape on a real group succeeds."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ssm = ctx.client("ssm")

    def _describe_group(name):
        groups = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[name]).get(
            "AutoScalingGroups", []
        )
        return groups[0] if groups else None

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

    def _subnet_id():
        subnets = ec2.describe_subnets(
            Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
        ).get("Subnets", [])
        if not subnets:
            raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
        return subnets[0]["SubnetId"]

    # Positive control: create a real group and update it with the identical call shape.
    lt_name = ctx.unique_name("sim2real-behav-as-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": _image_id(), "InstanceType": "t3.micro"},
        TagSpecifications=[{"ResourceType": "launch-template", "Tags": [{"Key": "sim2real", "Value": "true"}]}],
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    real_name = ctx.unique_name("sim2real-behav-as-real-")
    as_.create_auto_scaling_group(
        AutoScalingGroupName=real_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        DesiredCapacity=0,
        VPCZoneIdentifier=_subnet_id(),
        Tags=[{"Key": "sim2real", "Value": "true", "ResourceId": real_name, "ResourceType": "auto-scaling-group"}],
    )
    ctx.on_cleanup(
        lambda: as_.delete_auto_scaling_group(AutoScalingGroupName=real_name, ForceDelete=True)
    )

    as_.update_auto_scaling_group(AutoScalingGroupName=real_name, MinSize=1, MaxSize=2)
    control = _describe_group(real_name)
    assert control is not None and (control["MinSize"], control["MaxSize"]) == (1, 2), (
        f"positive control did not update to (1, 2): {control!r}"
    )

    bogus = ctx.unique_name("sim2real-behav-as-missing-")

    try:
        result = as_.update_auto_scaling_group(AutoScalingGroupName=bogus, MinSize=1, MaxSize=2)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(f"updating unknown group {bogus!r} SUCCEEDED and returned {result!r}")
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    # AWS renders the missing group as the literal "null", not the requested name.
    assert message == "AutoScalingGroup name not found - null", (
        f"unexpected ValidationError message: {message!r}"
    )
    # Must not have been implicitly created.
    assert _describe_group(bogus) is None, "failed update must not create the group"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
