"""create-listener-unsupported-protocol-version-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-listener-unsupported-protocol-version-rejected"
GROUP = "overly-permissive"
SERVICES = ["elbv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTargetGroup with ProtocolVersion HTTP2 on a TCP target group fails with InvalidConfigurationRequest
    and the exact message and creates nothing, while HTTP2 on an HTTP target group is accepted and stored."""
    elbv2 = ctx.client("elbv2")
    vpc_id = _create_vpc(ctx)

    bad_name = ctx.unique_name("sim2real-behav-tg-b-")

    code: str | None = None
    message: str | None = None
    try:
        bad_resp = elbv2.create_target_group(
            Name=bad_name,
            Protocol="TCP",
            Port=80,
            VpcId=vpc_id,
            TargetType="ip",
            ProtocolVersion="HTTP2",
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        message = exc.response["Error"].get("Message")
    else:
        # An over-permissive target that accepted this call still leaked a resource.
        bad_arn = bad_resp["TargetGroups"][0]["TargetGroupArn"]
        ctx.on_cleanup(lambda arn=bad_arn: elbv2.delete_target_group(TargetGroupArn=arn))
        raise AssertionError(
            "expected InvalidConfigurationRequest creating a TCP target group with "
            f"ProtocolVersion=HTTP2, but the call succeeded and created {bad_arn}"
        )
    # AWS rejects an unsupported ProtocolVersion+Protocol combination
    # (HTTP2 on a TCP target group) with InvalidConfigurationRequest.
    assert code == "InvalidConfigurationRequest", f"expected InvalidConfigurationRequest, got {code}"
    expected_message = "You cannot specify the protocol version for a target group with the 'TCP' protocol"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the target group was never created.
    not_found_code, not_found_message = _error_code(lambda: elbv2.describe_target_groups(Names=[bad_name]))
    assert not_found_code == "TargetGroupNotFound", (
        f"expected the rejected target group to not exist, got {not_found_code}"
    )
    expected_not_found = "One or more target groups not found"
    assert not_found_message == expected_not_found, (
        f"expected message {expected_not_found!r}, got {not_found_message!r}"
    )

    # Positive control: HTTP2 protocol version is valid for an HTTP target group.
    good_name = ctx.unique_name("sim2real-behav-tg-g-")
    resp = elbv2.create_target_group(
        Name=good_name,
        Protocol="HTTP",
        Port=80,
        VpcId=vpc_id,
        TargetType="ip",
        ProtocolVersion="HTTP2",
    )
    good_arn = resp["TargetGroups"][0]["TargetGroupArn"]
    ctx.on_cleanup(lambda arn=good_arn: elbv2.delete_target_group(TargetGroupArn=arn))

    # Independent read at the destination, through a different operation than the
    # create that produced it: describe must agree, not just the create response.
    described = elbv2.describe_target_groups(TargetGroupArns=[good_arn])["TargetGroups"][0]
    assert described["ProtocolVersion"] == "HTTP2", (
        f"expected the created target group's ProtocolVersion to read back as HTTP2 via "
        f"describe_target_groups, got {described.get('ProtocolVersion')!r}"
    )


def _error_code(fn) -> str:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded: {result!r}")


def _create_vpc(ctx: Any) -> str:
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(
        CidrBlock="10.102.0.0/16",
        TagSpecifications=[{
            "ResourceType": "vpc",
            "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vpc-")}],
        }],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    return vpc_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
