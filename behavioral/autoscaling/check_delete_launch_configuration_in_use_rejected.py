"""delete-launch-configuration-in-use-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-launch-configuration-in-use-rejected"
GROUP = "error-semantics"
SERVICES = ["autoscaling"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateLaunchConfiguration, withdrawn for accounts created on or after 2024-10-01, fails
    a complete request with the exact UnsupportedOperation refusal and persists nothing, while
    a launch-template-backed group creates and deletes cleanly in the same account."""
    asgc = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    ami_id = _valid_ami(ctx)
    az = _first_az(ctx)

    # Positive control: the account and credentials are otherwise healthy for Auto
    # Scaling -- a launch-template-backed group creates and deletes cleanly. This rules
    # out "everything is denied for this account" as the explanation for the refusal
    # asserted below.
    lt_name = ctx.unique_name("sim2real-behav-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": ami_id, "InstanceType": "t3.micro"},
    )
    ctx.on_cleanup(lambda: _best_effort_delete_lt(ec2, lt_name))

    asg_name = ctx.unique_name("sim2real-behav-asg-")
    asgc.create_auto_scaling_group(
        AutoScalingGroupName=asg_name,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        AvailabilityZones=[az],
        Tags=[{"Key": "sim2real", "Value": CHECK, "PropagateAtLaunch": False}],
        VPCZoneIdentifier=_network_zone_subnets(ctx, [az]),
    )
    asgc.delete_auto_scaling_group(AutoScalingGroupName=asg_name, ForceDelete=True)
    _poll_until_asg_gone(asgc, asg_name)

    # The specific refusal: a complete, otherwise-valid CreateLaunchConfiguration request
    # is rejected with UnsupportedOperation specifically -- separating "this account
    # cohort has the feature withdrawn" from "malformed request" or "no permissions at
    # all".
    lc_name = ctx.unique_name("sim2real-behav-lc-inuse-")
    code, message = _error_code_and_message(
        lambda: asgc.create_launch_configuration(
            LaunchConfigurationName=lc_name, ImageId=ami_id, InstanceType="t3.micro"
        )
    )
    assert code == "UnsupportedOperation", (
        f"expected the account-level UnsupportedOperation refusal for a complete "
        f"CreateLaunchConfiguration request, got {code!r} ({message!r})"
    )
    assert message == _LC_WITHDRAWN_MESSAGE, (
        f"expected the exact launch-configuration withdrawal message, got {message!r}"
    )

    # Effect absent: the rejected launch configuration was never persisted.
    still = asgc.describe_launch_configurations(LaunchConfigurationNames=[lc_name])[
        "LaunchConfigurations"
    ]
    assert still == [], f"rejected launch configuration must not exist, found: {still}"


# ===== helpers =====
_LC_WITHDRAWN_MESSAGE = (
    "The Launch Configuration creation operation is not available in your account. "
    "Use launch templates to create configuration templates for your Auto Scaling groups."
)


def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(
        f"expected CreateLaunchConfiguration to be rejected in this account cohort, but "
        f"it SUCCEEDED and returned {result!r}"
    )


def _poll_until_asg_gone(asgc, name: str, timeout_s: float = 120.0, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        groups = asgc.describe_auto_scaling_groups(AutoScalingGroupNames=[name])[
            "AutoScalingGroups"
        ]
        if not groups:
            return
        time.sleep(interval_s)
    raise AssertionError(
        f"positive control: {name!r} never finished deleting within {timeout_s}s"
    )


def _best_effort_delete_lt(ec2, name: str) -> None:
    """Delete the launch template; only its not-found code means already gone."""
    try:
        ec2.delete_launch_template(LaunchTemplateName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidLaunchTemplateName.NotFoundException":
            raise


def _valid_ami(ctx):
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2"
    )["Parameter"]["Value"]


def _first_az(ctx):
    ec2 = ctx.client("ec2")
    zones = ec2.describe_availability_zones(
        Filters=[{"Name": "region-name", "Values": [ctx.region]}, {"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
    )["AvailabilityZones"]
    return zones[0]["ZoneName"]


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
