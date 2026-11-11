"""op-contract-describeInternetGateways."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describeInternetGateways"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeInternetGateways reflects a freshly created gateway (unattached) and
    raises InvalidInternetGatewayID.NotFound for a nonexistent gateway ID."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-igw-")
    igw = ec2.create_internet_gateway(
        TagSpecifications=[
            {"ResourceType": "internet-gateway", "Tags": [{"Key": "Name", "Value": name}]}
        ]
    )["InternetGateway"]
    igw_id = igw["InternetGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))

    resp = ec2.describe_internet_gateways(InternetGatewayIds=[igw_id])
    gateways = resp.get("InternetGateways", [])
    assert len(gateways) == 1, f"expected exactly one gateway, got {gateways}"
    described = gateways[0]
    assert described["InternetGatewayId"] == igw_id, (
        f"expected {igw_id}, got {described['InternetGatewayId']}"
    )
    assert described["Attachments"] == [], "freshly created gateway should be unattached"
    assert "OwnerId" in described, f"expected OwnerId in response, got {described}"

    code, message = _error_of(
        lambda: ec2.describe_internet_gateways(InternetGatewayIds=["igw-0123456789abcdef0"])
    )
    assert code == "InvalidInternetGatewayID.NotFound", f"unexpected error code: {code}"
    assert message == "The internetGateway ID 'igw-0123456789abcdef0' does not exist", message


def _error_of(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises, because
    an emulator ACCEPTING an id real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected InvalidInternetGatewayID.NotFound, but call SUCCEEDED with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
