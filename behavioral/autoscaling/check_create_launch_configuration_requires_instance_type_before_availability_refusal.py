"""create-launch-configuration-requires-instance-type-before-availability-refusal."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-launch-configuration-requires-instance-type-before-availability-refusal"
GROUP = "validation-ordering"
SERVICES = ["autoscaling"]

_MISSING_INSTANCE_TYPE = (
    "ValidationError",
    "Valid requests must contain either the InstanceID parameter or both the ImageId and "
    "InstanceType parameters.",
)
_NOT_AVAILABLE = (
    "UnsupportedOperation",
    "The Launch Configuration creation operation is not available in your account. Use launch "
    "templates to create configuration templates for your Auto Scaling groups.",
)
_IMAGE_ID = "ami-0a1b2c3d4e5f6a7b8"


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code}, got {got_code}: {got_message!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateLaunchConfiguration refuses a request missing both InstanceId and InstanceType
    with ValidationError even where a complete request only reaches this account's own
    UnsupportedOperation refusal: the required-parameter check runs first.
    """
    asg = ctx.client("autoscaling")
    complete_name = ctx.unique_name("sim2real-behav-as-lc-complete-")
    incomplete_name = ctx.unique_name("sim2real-behav-as-lc-incomplete-")

    # Positive control: a complete request (ImageId + InstanceType, no InstanceId) passes the
    # required-parameter check and reaches this account's own availability refusal.
    expect_error(
        lambda: asg.create_launch_configuration(
            LaunchConfigurationName=complete_name, ImageId=_IMAGE_ID, InstanceType="t3.micro"
        ),
        *_NOT_AVAILABLE,
    )

    # The same request with InstanceType (and InstanceId) omitted never reaches that refusal:
    # it is refused for the missing parameter instead.
    expect_error(
        lambda: asg.create_launch_configuration(
            LaunchConfigurationName=incomplete_name, ImageId=_IMAGE_ID
        ),
        *_MISSING_INSTANCE_TYPE,
    )

    described = asg.describe_launch_configurations(
        LaunchConfigurationNames=[complete_name, incomplete_name]
    )["LaunchConfigurations"]
    assert described == [], (
        f"expected neither refused launch configuration to exist, found {described!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
