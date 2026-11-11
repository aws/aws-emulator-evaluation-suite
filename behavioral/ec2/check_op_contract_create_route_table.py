"""op-contract-create-route-table."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-create-route-table"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateRouteTable creates a table that DescribeRouteTables shows in the VPC with exactly one active
    local route for 10.80.0.0/16; a nonexistent VpcId fails with InvalidVpcID.NotFound."""
    ec2 = ctx.client("ec2")

    vpc = ec2.create_vpc(
        CidrBlock="10.80.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    resp = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[{"ResourceType": "route-table", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )
    rt_id = resp["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=rt_id))

    # Independent read at the destination — not the create call's own echo.
    described = ec2.describe_route_tables(RouteTableIds=[rt_id])["RouteTables"][0]
    assert described["VpcId"] == vpc_id, f"expected VpcId {vpc_id}, got {described['VpcId']}"
    local_routes = [r for r in described["Routes"] if r.get("GatewayId") == "local"]
    assert len(local_routes) == 1, f"expected exactly 1 local route, got {described['Routes']}"
    assert local_routes[0]["DestinationCidrBlock"] == "10.80.0.0/16", (
        f"expected local route for 10.80.0.0/16, got {local_routes[0]['DestinationCidrBlock']}"
    )
    assert local_routes[0]["State"] == "active", f"expected local route active, got {local_routes[0]['State']}"

    # Error boundary: a nonexistent VpcId must be rejected. Always-invalid input (the id can
    # never become valid), so there is no restore leg; the create above is the positive control.
    code = _error_code(lambda: ec2.create_route_table(VpcId="vpc-00000000000000000"))
    assert code == "InvalidVpcID.NotFound", f"expected InvalidVpcID.NotFound, got {code!r}"


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
