"""op-contract-describeEgressOnlyInternetGateways."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeEgressOnlyInternetGateways"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeEgressOnlyInternetGateways reflects a real attachment and treats a bogus ID as a
    non-matching filter rather than an error."""
    ec2 = ctx.client("ec2")

    vpc_id = _get_or_create_vpc(ctx, ec2)

    eigw = ec2.create_egress_only_internet_gateway(VpcId=vpc_id)["EgressOnlyInternetGateway"]
    eigw_id = eigw["EgressOnlyInternetGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_egress_only_internet_gateway(EgressOnlyInternetGatewayId=eigw_id))

    # --- success path: the gateway shows up, attached to our VPC ---
    deadline = time.monotonic() + 30
    attachment = None
    while time.monotonic() < deadline:
        resp = ec2.describe_egress_only_internet_gateways(EgressOnlyInternetGatewayIds=[eigw_id])
        gateways = resp["EgressOnlyInternetGateways"]
        assert len(gateways) == 1, f"expected exactly 1 gateway for {eigw_id}, got {len(gateways)}"
        attachments = gateways[0]["Attachments"]
        if attachments and attachments[0]["State"] == "attached":
            attachment = attachments[0]
            break
        time.sleep(1.5)
    assert attachment is not None, "egress-only IGW never reached 'attached' state"
    assert attachment["VpcId"] == vpc_id, f"expected attachment to {vpc_id}, got {attachment['VpcId']}"

    # A describe call with no filters must also include it (list semantics, not just lookup-by-id).
    all_gateways = ec2.describe_egress_only_internet_gateways()["EgressOnlyInternetGateways"]
    assert any(g["EgressOnlyInternetGatewayId"] == eigw_id for g in all_gateways), (
        f"expected {eigw_id} to appear in an unfiltered DescribeEgressOnlyInternetGateways"
    )

    # --- boundary: a well-formed but nonexistent gateway ID is treated as an ID filter, not a
    # specific-resource lookup -- real AWS does not raise for this, it simply matches nothing ---
    bogus_id = "eigw-0123456789abcdef0"
    empty = ec2.describe_egress_only_internet_gateways(EgressOnlyInternetGatewayIds=[bogus_id])
    assert empty["EgressOnlyInternetGateways"] == [], (
        "describing a nonexistent egress-only IGW ID should match nothing, not raise or return other gateways"
    )


def _get_or_create_vpc(ctx, ec2):
    """Create a fresh VPC for the test; if the account is already at its VPC quota
    (a real, observed possibility, not a bug in this check), fall back to reusing an
    existing VPC instead -- an egress-only IGW attachment doesn't require a brand-new VPC."""
    try:
        vpc = ec2.create_vpc(
            CidrBlock="10.211.0.0/16",
            AmazonProvidedIpv6CidrBlock=True,
            TagSpecifications=[
                {
                    "ResourceType": "vpc",
                    "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-eigw-vpc-")}],
                }
            ],
        )["Vpc"]
        vpc_id = vpc["VpcId"]
        ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
        return vpc_id
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "VpcLimitExceeded":
            raise

    vpcs = ec2.describe_vpcs(VpcIds=[ctx.network().vpc_id])["Vpcs"]
    if not vpcs:
        raise AssertionError("VPC quota exhausted and no existing VPC available to reuse")
    default = [v for v in vpcs if v.get("IsDefault")]
    return (default[0] if default else vpcs[0])["VpcId"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
