"""create-local-gateway-route-table-vpc-association-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-local-gateway-route-table-vpc-association-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateLocalGatewayRouteTableVpcAssociation with a real VPC and an unknown route table id is refused with
    InvalidLocalGatewayRouteTableID.NotFound and its exact message: the valid VPC does not bypass the check.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(
        CidrBlock="10.222.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    code, message = _client_error(
        lambda: ec2.create_local_gateway_route_table_vpc_association(
            LocalGatewayRouteTableId="lgw-rtb-00000000000000000",
            VpcId=vpc_id,
        )
    )
    assert code == "InvalidLocalGatewayRouteTableID.NotFound", (
        f"expected InvalidLocalGatewayRouteTableID.NotFound, got {code!r}"
    )
    expected_message = "The LocalGateway Route Table ID 'lgw-rtb-00000000000000000' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _client_error(fn):
    """Call *fn*; return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
