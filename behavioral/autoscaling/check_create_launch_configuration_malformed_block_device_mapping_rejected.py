"""create-launch-configuration-malformed-block-device-mapping-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-launch-configuration-malformed-block-device-mapping-rejected"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateLaunchConfiguration rejects a gp2 VolumeSize above 16384 GiB with ValidationError, and
    rejects a well-formed request with UnsupportedOperation on accounts where launch configuration
    creation is unavailable; neither is stored."""
    asgc = ctx.client("autoscaling")
    ami_id = _latest_al2_ami(ctx)

    malformed_name = ctx.unique_name("sim2real-behav-malformed-lc-")
    malformed_code, malformed_message = _error_code(
        lambda: asgc.create_launch_configuration(
            LaunchConfigurationName=malformed_name,
            ImageId=ami_id,
            InstanceType="t3.micro",
            BlockDeviceMappings=[
                {
                    "DeviceName": "/dev/sdf",
                    "Ebs": {"VolumeSize": 16385, "VolumeType": "gp2"},
                }
            ],
        )
    )
    assert malformed_code == "ValidationError", (
        f"expected ValidationError, got {malformed_code}"
    )
    assert malformed_message == (
        "1 validation error detected: Value '16385' at "
        "'blockDeviceMappings.1.member.ebs.volumeSize' failed to satisfy constraint: "
        "Member must have value less than or equal to 16384"
    ), f"expected the exact VolumeSize constraint message, got {malformed_message!r}"

    names = [
        lc["LaunchConfigurationName"]
        for lc in asgc.describe_launch_configurations(LaunchConfigurationNames=[malformed_name])[
            "LaunchConfigurations"
        ]
    ]
    assert names == [], f"malformed launch configuration should not exist, found: {names}"

    # Newer accounts cannot create launch configurations at all, so a valid request fails too.
    valid_name = ctx.unique_name("sim2real-behav-valid-lc-")
    try:
        created = asgc.create_launch_configuration(
            LaunchConfigurationName=valid_name,
            ImageId=ami_id,
            InstanceType="t3.micro",
            BlockDeviceMappings=[
                {"DeviceName": "/dev/sdf", "Ebs": {"VolumeSize": 8, "VolumeType": "gp2"}}
            ],
        )
    except ClientError as e:
        valid_code = e.response["Error"]["Code"]
        valid_message = e.response["Error"].get("Message", "")
    else:
        ctx.on_cleanup(lambda: asgc.delete_launch_configuration(LaunchConfigurationName=valid_name))
        raise AssertionError(
            f"expected the well-formed CreateLaunchConfiguration to be refused with "
            f"UnsupportedOperation, but it SUCCEEDED: {created!r}"
        )
    assert valid_code == "UnsupportedOperation", (
        f"expected UnsupportedOperation, got {valid_code}: {valid_message!r}"
    )
    assert valid_message == _LC_WITHDRAWN_MESSAGE, (
        f"expected the exact launch-configuration withdrawal message, got {valid_message!r}"
    )
    names = [
        lc["LaunchConfigurationName"]
        for lc in asgc.describe_launch_configurations(LaunchConfigurationNames=[valid_name])[
            "LaunchConfigurations"
        ]
    ]
    assert names == [], f"rejected launch configuration should not exist, found: {names}"


_LC_WITHDRAWN_MESSAGE = (
    "The Launch Configuration creation operation is not available in your account. "
    "Use launch templates to create configuration templates for your Auto Scaling groups."
)


def _error_code(fn):
    """Call fn(); return its error code and message. Success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"][
        "Value"
    ]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

