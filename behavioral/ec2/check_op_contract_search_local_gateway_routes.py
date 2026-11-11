"""op-contract-search-local-gateway-routes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-search-local-gateway-routes"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """SearchLocalGatewayRoutes fails with InvalidLocalGatewayRouteTableID.NotFound for an unknown table
    and with DryRunOperation under DryRun (exact messages); DescribeLocalGatewayRouteTables finds no
    such table, and a real table, when present, returns a Routes list."""
    ec2 = ctx.client("ec2")

    err = _error(
        lambda: ec2.search_local_gateway_routes(
            LocalGatewayRouteTableId="lgw-rtb-00000000000000000",
            Filters=[{"Name": "state", "Values": ["active"]}],
        )
    )
    assert err["Code"] == "InvalidLocalGatewayRouteTableID.NotFound", f"unexpected error: {err!r}"
    assert err.get("Message") == "The LocalGateway Route Table ID 'lgw-rtb-00000000000000000' does not exist", (
        f"unexpected message: {err.get('Message')!r}"
    )

    dry = _error(
        lambda: ec2.search_local_gateway_routes(
            LocalGatewayRouteTableId="lgw-rtb-00000000000000000",
            Filters=[{"Name": "state", "Values": ["active"]}],
            DryRun=True,
        )
    )
    assert dry["Code"] == "DryRunOperation", f"expected DryRunOperation, got {dry!r}"
    assert dry.get("Message") == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected message: {dry.get('Message')!r}"
    )

    route_tables = ec2.describe_local_gateway_route_tables().get("LocalGatewayRouteTables", [])
    if route_tables:
        rtb_id = route_tables[0]["LocalGatewayRouteTableId"]
        resp = ec2.search_local_gateway_routes(
            LocalGatewayRouteTableId=rtb_id, Filters=[{"Name": "state", "Values": ["active"]}]
        )
        assert "Routes" in resp, f"unexpected response shape: {resp}"
    else:
        matches = ec2.describe_local_gateway_route_tables(
            LocalGatewayRouteTableIds=["lgw-rtb-00000000000000000"]
        ).get("LocalGatewayRouteTables", [])
        assert matches == [], f"expected no match for a bogus id, got: {matches}"


def _error(fn):
    """Call fn(); return its ClientError Error dict. An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
