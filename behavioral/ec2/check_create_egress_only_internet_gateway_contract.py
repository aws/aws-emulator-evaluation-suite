"""create-egress-only-internet-gateway-contract."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-egress-only-internet-gateway-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEgressOnlyInternetGateway attaches the new gateway to the VPC (attaching or attached, also by
    DescribeEgressOnlyInternetGateways), and an unknown 17-character VPC id is refused with InvalidVpcId.Malformed.
    """
    ec2 = ctx.client("ec2")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.77.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc")]
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    resp = ec2.create_egress_only_internet_gateway(
        VpcId=vpc_id, TagSpecifications=[_tag_spec(ctx, "egress-only-internet-gateway")]
    )
    eigw = resp["EgressOnlyInternetGateway"]
    eigw_id = eigw["EgressOnlyInternetGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_egress_only_internet_gateway(EgressOnlyInternetGatewayId=eigw_id))

    attachments = eigw["Attachments"]
    assert attachments, "expected the new egress-only IGW to have an attachment"
    assert any(a["VpcId"] == vpc_id for a in attachments)
    assert attachments[0]["State"] in ("attaching", "attached")

    described = ec2.describe_egress_only_internet_gateways(EgressOnlyInternetGatewayIds=[eigw_id])[
        "EgressOnlyInternetGateways"
    ][0]
    assert any(a["VpcId"] == vpc_id for a in described["Attachments"])

    # Error boundary: a made-up 17-character VPC id is refused as InvalidVpcId.Malformed rather than
    # not found.
    code = _error_code(
        lambda: ec2.create_egress_only_internet_gateway(VpcId="vpc-0123456789abcdef0")
    )
    assert code == "InvalidVpcId.Malformed", (
        f"expected InvalidVpcId.Malformed, got {code!r}"
    )


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _tag_spec(ctx, resource_type):
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-behav-{resource_type}-")}],
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
