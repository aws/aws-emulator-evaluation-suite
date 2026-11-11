"""launch-configuration-user-data-base64-round-trip."""
from __future__ import annotations

import base64
import os

from behavioral_harness import tags

CHECK = "launch-configuration-user-data-base64-round-trip"
GROUP = "representation"
SERVICES = ["autoscaling"]

_WITHDRAWAL_MESSAGE = (
    "The Launch Configuration creation operation is not available in your account. "
    "Use launch templates to create configuration templates for your Auto Scaling groups."
)


@tags("axis:rejection", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateLaunchConfiguration is refused with UnsupportedOperation on accounts that never created
    one, so assert the exact refusal and that no launch configuration exists; a successful create
    fails.
    """
    autoscaling = ctx.client("autoscaling")

    # Positive control: an unrelated read proves the account and credentials are
    # otherwise healthy for autoscaling, so a broadly-denied account is never
    # mistaken for one where only launch-configuration creation is frozen.
    autoscaling.describe_account_limits()

    ami = _al2_ami_id(ctx)

    raw = bytes(os.urandom(256))
    # flip a few bytes into the full 0x00-0xff range so any lossy re-encoding would show
    raw = bytes([0x00, 0x01, 0xFF, 0xFE, 0x80, 0x7F]) + raw
    encoded = base64.b64encode(raw).decode("ascii")

    lc_name = ctx.unique_name("sim2real-lc-")
    error = None
    try:
        created = autoscaling.create_launch_configuration(
            LaunchConfigurationName=lc_name, ImageId=ami, InstanceType="t3.micro", UserData=encoded,
        )
    except Exception as err:  # noqa: BLE001
        response = getattr(err, "response", None)
        if response is None:
            raise
        error = response.get("Error", {})
    else:
        ctx.on_cleanup(lambda: autoscaling.delete_launch_configuration(LaunchConfigurationName=lc_name))
        raise AssertionError(
            f"expected CreateLaunchConfiguration to be refused with UnsupportedOperation on this "
            f"account, but it SUCCEEDED: {created!r}"
        )

    if error is not None:
        # AWS disables CreateLaunchConfiguration for accounts that never created one (steering
        # new usage to launch templates), so the UserData round-trip is unreachable there.
        assert error.get("Code") == "UnsupportedOperation", (error.get("Code"), error.get("Message"))
        assert error.get("Message") == _WITHDRAWAL_MESSAGE, (
            f"got UnsupportedOperation but not the exact withdrawal message: {error.get('Message')!r}"
        )
        found = autoscaling.describe_launch_configurations(
            LaunchConfigurationNames=[lc_name]
        )["LaunchConfigurations"]
        assert found == [], (
            f"expected no launch configuration named {lc_name!r} after AWS refused the create "
            f"with UnsupportedOperation, found {found!r}"
        )
        return


def _al2_ami_id(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"]["Value"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
