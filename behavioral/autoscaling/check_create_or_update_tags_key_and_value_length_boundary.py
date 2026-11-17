"""create-or-update-tags-key-and-value-length-boundary."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-or-update-tags-key-and-value-length-boundary"
GROUP = "tags"
SERVICES = ["autoscaling", "ec2", "ssm"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(
        Name="/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
    )["Parameter"]["Value"]


def _make_group(ctx, as_, ec2) -> str:
    lt_name = ctx.unique_name("sim2real-behav-asg-lt-")
    ec2.create_launch_template(
        LaunchTemplateName=lt_name,
        LaunchTemplateData={"ImageId": _ami(ctx), "InstanceType": "t3.micro"},
    )
    ctx.on_cleanup(lambda: ec2.delete_launch_template(LaunchTemplateName=lt_name))

    name = ctx.unique_name("sim2real-behav-asg-")
    as_.create_auto_scaling_group(
        AutoScalingGroupName=name,
        MinSize=0,
        MaxSize=0,
        DesiredCapacity=0,
        LaunchTemplate={"LaunchTemplateName": lt_name, "Version": "$Latest"},
        AvailabilityZones=[ctx.network().availability_zones[0]],
    )
    ctx.on_cleanup(
        lambda: as_.delete_auto_scaling_group(AutoScalingGroupName=name, ForceDelete=True)
    )
    return name


def _group_tags(as_, name):
    return as_.describe_tags(Filters=[{"Name": "auto-scaling-group", "Values": [name]}])["Tags"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag Key of 128 characters and a Value of 256 characters are accepted and round-trip;
    one character over either declared maximum is rejected with its exact validation message."""
    as_ = ctx.client("autoscaling")
    ec2 = ctx.client("ec2")
    name = _make_group(ctx, as_, ec2)

    max_key = "k" * 128
    max_value = "v" * 256
    as_.create_or_update_tags(
        Tags=[
            {
                "ResourceId": name,
                "ResourceType": "auto-scaling-group",
                "Key": max_key,
                "Value": max_value,
                "PropagateAtLaunch": False,
            }
        ]
    )
    present = [t for t in _group_tags(as_, name) if t["Key"] == max_key]
    assert len(present) == 1, f"expected the boundary tag to round-trip once, got {present!r}"
    assert present[0]["Value"] == max_value, (
        f"expected the 256-character value to round-trip unchanged, got {present[0]['Value']!r}"
    )

    over_key = "k" * 129
    code, message = _error(
        lambda: as_.create_or_update_tags(
            Tags=[
                {
                    "ResourceId": name,
                    "ResourceType": "auto-scaling-group",
                    "Key": over_key,
                    "Value": "v",
                    "PropagateAtLaunch": False,
                }
            ]
        )
    )
    assert code == "ValidationError", f"a 129-character key gave {code}: {message!r}"
    assert message == (
        "1 validation error detected: Value '"
        + over_key
        + "' at 'tags.1.member.key' failed to satisfy constraint: "
        "Member must have length less than or equal to 128"
    ), f"unexpected message for a 129-character key: {message!r}"

    over_value = "v" * 257
    code, message = _error(
        lambda: as_.create_or_update_tags(
            Tags=[
                {
                    "ResourceId": name,
                    "ResourceType": "auto-scaling-group",
                    "Key": "behav-over-value",
                    "Value": over_value,
                    "PropagateAtLaunch": False,
                }
            ]
        )
    )
    assert code == "ValidationError", f"a 257-character value gave {code}: {message!r}"
    assert message == (
        "1 validation error detected: Value '"
        + over_value
        + "' at 'tags.1.member.value' failed to satisfy constraint: "
        "Member must have length less than or equal to 256"
    ), f"unexpected message for a 257-character value: {message!r}"

    remaining = [t for t in _group_tags(as_, name) if t["Key"] in (over_key, "behav-over-value")]
    assert remaining == [], f"a rejected tag must not be stored: {remaining!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
