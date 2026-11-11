"""op-contract-describe-local-gateway-route-table-vpc-associations."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-describe-local-gateway-route-table-vpc-associations"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeLocalGatewayRouteTableVpcAssociations: success-path shape + DryRun boundary.

    Requires Outposts-attached Local Gateways to have real associations; on a plain
    account the contract under test is the response shape and DryRun semantics.
    """
    ec2 = ctx.client("ec2")

    resp = ec2.describe_local_gateway_route_table_vpc_associations()
    assert "LocalGatewayRouteTableVpcAssociations" in resp, f"missing key: {sorted(resp)}"
    rows = resp["LocalGatewayRouteTableVpcAssociations"]
    assert isinstance(rows, list), f"expected a list, got {type(rows).__name__}: {rows!r}"
    for row in rows:
        assert "LocalGatewayRouteTableVpcAssociationId" in row, f"missing id: {sorted(row)}"
        assert "VpcId" in row, f"missing VpcId: {sorted(row)}"

    # Filtering by our own (real) VPC that has no local gateway association narrows to
    # empty, not an error.
    resp2 = ec2.describe_local_gateway_route_table_vpc_associations(
        Filters=[{"Name": "vpc-id", "Values": ["vpc-00000000000000000"]}]
    )
    got = resp2["LocalGatewayRouteTableVpcAssociations"]
    assert got == [], f"expected no associations for an unassociated vpc-id filter, got {got!r}"

    # Error boundary: DryRun.
    code, message = _client_error(
        lambda: ec2.describe_local_gateway_route_table_vpc_associations(DryRun=True)
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == _DRY_RUN_MESSAGE, f"expected {_DRY_RUN_MESSAGE!r}, got {message!r}"


def _client_error(fn):
    """Call fn() and return the (code, message) it is refused with; an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
