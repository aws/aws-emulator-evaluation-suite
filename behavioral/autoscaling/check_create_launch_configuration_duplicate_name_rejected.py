"""create-launch-configuration-duplicate-name-rejected."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "create-launch-configuration-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A duplicate LaunchConfiguration name is rejected with AlreadyExists and the original is not
    overwritten; on accounts where the API is withdrawn, the exact UnsupportedOperation is asserted
    and nothing is created."""
    from botocore.exceptions import ClientError

    autoscaling = ctx.client("autoscaling")
    ami_id = _latest_al2_ami(ctx)

    lc_name = ctx.unique_name("sim2real-lc-dup-")
    try:
        autoscaling.create_launch_configuration(
            LaunchConfigurationName=lc_name, ImageId=ami_id, InstanceType="t3.micro"
        )
    except ClientError as err:
        # Accounts created on or after 2023-09-15 cannot call CreateLaunchConfiguration at all.
        code = err.response["Error"]["Code"]
        message = err.response["Error"].get("Message", "")
        assert code == "UnsupportedOperation", (
            f"expected CreateLaunchConfiguration to succeed or be withdrawn with "
            f"UnsupportedOperation, got {code!r}: {message!r}"
        )
        assert message == _LC_WITHDRAWN_MESSAGE, (
            f"expected the exact launch-configuration withdrawal message, got {message!r}"
        )
        # Positive control: the account and credentials are otherwise healthy for autoscaling.
        autoscaling.describe_launch_configurations(MaxRecords=1)
        # Effect absent: the configuration was never created.
        configs = autoscaling.describe_launch_configurations(
            LaunchConfigurationNames=[lc_name]
        )["LaunchConfigurations"]
        assert configs == [], f"expected no launch configuration named {lc_name!r}, got {configs}"
        return
    ctx.on_cleanup(lambda: _safe_call(lambda: autoscaling.delete_launch_configuration(
        LaunchConfigurationName=lc_name
    )))

    code = _error_code(
        lambda: autoscaling.create_launch_configuration(
            LaunchConfigurationName=lc_name, ImageId=ami_id, InstanceType="t3.small"
        )
    )
    # message unverified: no recent account can create a launch configuration to collide with
    assert code == "AlreadyExists", f"expected AlreadyExists, got {code!r}"

    # Effect absent: the original configuration's parameters are unchanged (not overwritten).
    configs = autoscaling.describe_launch_configurations(LaunchConfigurationNames=[lc_name])[
        "LaunchConfigurations"
    ]
    assert len(configs) == 1, f"expected exactly 1 launch configuration named {lc_name!r}, got {configs}"
    assert configs[0]["InstanceType"] == "t3.micro", (
        f"expected InstanceType t3.micro to survive the rejected duplicate, "
        f"got {configs[0]['InstanceType']!r}"
    )

    # Positive control: a genuinely new name succeeds.
    other_name = ctx.unique_name("sim2real-lc-dup-other-")
    autoscaling.create_launch_configuration(
        LaunchConfigurationName=other_name, ImageId=ami_id, InstanceType="t3.small"
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: autoscaling.delete_launch_configuration(
        LaunchConfigurationName=other_name
    )))
    configs = autoscaling.describe_launch_configurations(LaunchConfigurationNames=[other_name])[
        "LaunchConfigurations"
    ]
    assert len(configs) == 1, f"expected exactly 1 launch configuration named {other_name!r}, got {configs}"
    assert configs[0]["InstanceType"] == "t3.small", (
        f"expected the new configuration's own InstanceType t3.small, got {configs[0]['InstanceType']!r}"
    )


_LC_WITHDRAWN_MESSAGE = (
    "The Launch Configuration creation operation is not available in your account. "
    "Use launch templates to create configuration templates for your Auto Scaling groups."
)


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")[
        "Parameter"
    ]["Value"]


def _safe_call(fn: Callable[[], Any]) -> None:
    """Run a teardown delete; only a not-found error means already gone, anything else raises."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] in _NOT_FOUND_CODES:
            return
        if not (err["Code"] == "ValidationError" and "not found" in err.get("Message", "")):
            raise


_NOT_FOUND_CODES = ("InvalidLaunchTemplateName.NotFoundException", "InvalidLaunchTemplateId.NotFound")


def _error_code(fn: Callable[[], Any]) -> str:
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because
    accepting a call AWS refuses is itself the failure."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"]
    raise AssertionError(f"expected the duplicate-name call to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
