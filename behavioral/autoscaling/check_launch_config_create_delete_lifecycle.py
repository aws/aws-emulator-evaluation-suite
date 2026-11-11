"""launch-config-create-delete-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError


from behavioral_harness import tags


CHECK = "launch-config-create-delete-lifecycle"
GROUP = 'overly-permissive'
SERVICES = ['autoscaling']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateLaunchConfiguration is rejected with UnsupportedOperation, a launch-template group succeeds,
    and CreateAutoScalingGroup naming a launch configuration that does not exist is rejected."""
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

    def _error(fn):
        try:
            result = fn()
        except ClientError as exc:
            return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
        raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

    az = ctx.network().availability_zones[0]
    image_id = _image_id()
    lc_name = ctx.unique_name("sim2real-behav-as-lc-")

    # Positive control: the account and credentials are otherwise healthy for
    # CreateAutoScalingGroup — a launch template (the modern replacement AWS steers every
    # withdrawn account toward) works. Without this, the withdrawal assertion below would be
    # indistinguishable from "every autoscaling call in this account fails".
    lt_name = ctx.unique_name("sim2real-behav-as-lt-")
    lt = ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": image_id, "InstanceType": "t3.micro"},
    )["LaunchTemplate"]
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateId=lt["LaunchTemplateId"]))

    control_asg = ctx.unique_name("sim2real-behav-as-ctl-")
    as_.create_auto_scaling_group(
        AutoScalingGroupName=control_asg,
        LaunchTemplate={"LaunchTemplateId": lt["LaunchTemplateId"], "Version": "$Latest"},
        MinSize=0,
        MaxSize=1,
        AvailabilityZones=[az],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    ctx.on_cleanup(lambda: as_.delete_auto_scaling_group(AutoScalingGroupName=control_asg))
    live = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[control_asg])["AutoScalingGroups"]
    assert len(live) == 1
    assert live[0]["LaunchTemplate"]["LaunchTemplateId"] == lt["LaunchTemplateId"]

    # The withdrawal itself is the contract: CreateLaunchConfiguration must be rejected outright,
    # and nothing must appear afterward under that name.
    code, message = _error(
        lambda: as_.create_launch_configuration(
            LaunchConfigurationName=lc_name,
            ImageId=image_id,
            InstanceType="t3.micro",
        )
    )
    assert code == "UnsupportedOperation", (
        f"expected CreateLaunchConfiguration to be withdrawn with UnsupportedOperation on this "
        f"account, got {code!r}"
    )
    expected = ("The Launch Configuration creation operation is not available in your account. "
                "Use launch templates to create configuration templates for your Auto Scaling groups.")
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    resp = as_.describe_launch_configurations(LaunchConfigurationNames=[lc_name])
    assert resp["LaunchConfigurations"] == [], "no launch configuration should exist after the rejected create"

    # Overly-permissive guard: an ASG cannot be created against a launch-configuration name that
    # was never created — the positive control above proves CreateAutoScalingGroup itself works
    # on this account, so a target that accepts this reference too is specifically failing
    # reference-integrity validation, not merely failing every request.
    asg_name = ctx.unique_name("sim2real-behav-as-grp-")
    code2, message2 = _error(
        lambda: as_.create_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            LaunchConfigurationName=lc_name,
            MinSize=0,
            MaxSize=1,
            AvailabilityZones=[az],
            VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
        )
    )
    assert code2 == "ValidationError", f"expected ValidationError referencing missing launch config, got {code2!r}"
    expected = (f"Launch configuration name not found - A launch configuration with the name: "
                f"{lc_name} does not exist")
    assert message2 == expected, f"expected message {expected!r}, got {message2!r}"
    resp2 = as_.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])["AutoScalingGroups"]
    assert resp2 == [], "a phantom ASG must not have been created"


def _network_zone_subnets(ctx, zones) -> str:
    """The shared network's subnets in `zones`, comma-separated for VPCZoneIdentifier."""
    by_zone = ctx.network().subnets
    missing = [z for z in zones if z not in by_zone]
    if missing:
        raise AssertionError(f"the run's shared network has no subnet in {missing}")
    return ",".join(by_zone[z] for z in zones)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
