"""launch-configuration-delete-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "launch-configuration-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["autoscaling"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Where CreateLaunchConfiguration is withdrawn, it is refused with UnsupportedOperation (exact
    code and message) and the configuration never exists; where still permitted, the launch
    configuration is created, listed, deleted and then no longer listed."""
    from botocore.exceptions import ClientError

    asg = ctx.client("autoscaling")

    # Positive control: autoscaling access itself is healthy, so a refusal below is
    # about launch configurations specifically, not a blanket permissions problem.
    asg.describe_account_limits()

    ami_id = _al2023_ami(ctx)
    lc_name = ctx.unique_name("sim2real-behav-lc-")

    try:
        asg.create_launch_configuration(
            LaunchConfigurationName=lc_name,
            ImageId=ami_id,
            InstanceType="t3.micro",
        )
    except ClientError as exc:
        error = exc.response["Error"]
        if error["Code"] == "UnsupportedOperation":
            message = error.get("Message", "")
            expected = ("The Launch Configuration creation operation is not available in your account. "
                        "Use launch templates to create configuration templates for your Auto Scaling groups.")
            assert message == expected, (
                f"expected the UnsupportedOperation message {expected!r}, got {error!r}"
            )
            listed = asg.describe_launch_configurations(
                LaunchConfigurationNames=[lc_name]
            )["LaunchConfigurations"]
            assert listed == [], (
                f"a launch configuration refused by CreateLaunchConfiguration must not exist: {listed}"
            )
            return
        raise

    ctx.on_cleanup(lambda: asg.delete_launch_configuration(LaunchConfigurationName=lc_name))

    listed = asg.describe_launch_configurations(LaunchConfigurationNames=[lc_name])[
        "LaunchConfigurations"
    ]
    assert any(lc["LaunchConfigurationName"] == lc_name for lc in listed), (
        f"launch configuration not visible after CreateLaunchConfiguration: {listed}"
    )

    asg.delete_launch_configuration(LaunchConfigurationName=lc_name)

    listed_after = asg.describe_launch_configurations(LaunchConfigurationNames=[lc_name])[
        "LaunchConfigurations"
    ]
    assert listed_after == [], f"launch configuration still listed after delete: {listed_after}"


def _al2023_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    try:
        name = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
        return ssm.get_parameter(Name=name)["Parameter"]["Value"]
    except Exception:
        ec2 = ctx.client("ec2")
        images = ec2.describe_images(
            Owners=["amazon"],
            Filters=[
                {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
                {"Name": "state", "Values": ["available"]},
            ],
        )["Images"]
        images.sort(key=lambda im: im["CreationDate"], reverse=True)
        return images[0]["ImageId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
