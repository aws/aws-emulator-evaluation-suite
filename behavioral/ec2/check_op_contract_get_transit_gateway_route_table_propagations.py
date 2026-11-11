"""op-contract-get-transit-gateway-route-table-propagations."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-transit-gateway-route-table-propagations"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTransitGatewayRouteTablePropagations: empty list for a fresh route table, NotFound for a bogus id."""
    ec2 = ctx.client("ec2")

    route_table_id = _get_fresh_transit_gateway_route_table(ec2, ctx)

    resp = ec2.get_transit_gateway_route_table_propagations(TransitGatewayRouteTableId=route_table_id)
    assert "TransitGatewayRouteTablePropagations" in resp, f"missing key in response: {resp!r}"
    assert resp["TransitGatewayRouteTablePropagations"] == [], (
        "a fresh transit gateway route table should have no propagations"
    )

    code = _error_code(
        lambda: ec2.get_transit_gateway_route_table_propagations(
            TransitGatewayRouteTableId="tgw-rtb-00000000000000000"
        )
    )
    assert "notfound" in code.lower(), f"unexpected error code {code!r}"
    assert "routetable" in code.lower(), f"expected a route-table-specific NotFound code, got {code!r}"


def _get_fresh_transit_gateway_route_table(ec2, ctx) -> str:
    """Return the id of a freshly created (propagation-free) transit gateway route
    table, falling back to a new route table on an existing transit gateway if the
    account is already at the transit-gateway-count limit."""
    try:
        tgw_name = ctx.unique_name("sim2real-tgw-")
        tgw_resp = ec2.create_transit_gateway(
            Description=tgw_name,
            Options={
                "AutoAcceptSharedAttachments": "disable",
                "DefaultRouteTableAssociation": "enable",
                "DefaultRouteTablePropagation": "enable",
            },
            TagSpecifications=[
                {"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": tgw_name}]}
            ],
        )["TransitGateway"]
        tgw_id = tgw_resp["TransitGatewayId"]
        ctx.on_cleanup(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id))
        route_table_id = tgw_resp["Options"]["AssociationDefaultRouteTableId"]

        def _tgw_state():
            tgws = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"]
            return tgws[0]["State"] if tgws else None

        _poll_until(_tgw_state, lambda s: s == "available", timeout_s=180, interval_s=5)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "TransitGatewayLimitExceeded":
            raise
        tgws = ec2.describe_transit_gateways(Filters=[{"Name": "state", "Values": ["available"]}])[
            "TransitGateways"
        ]
        if not tgws:
            raise
        tgw_id = tgws[0]["TransitGatewayId"]
        rtb_name = ctx.unique_name("sim2real-tgw-rtb-")
        route_table = ec2.create_transit_gateway_route_table(
            TransitGatewayId=tgw_id,
            TagSpecifications=[
                {"ResourceType": "transit-gateway-route-table", "Tags": [{"Key": "Name", "Value": rtb_name}]}
            ],
        )["TransitGatewayRouteTable"]
        route_table_id = route_table["TransitGatewayRouteTableId"]
        ctx.on_cleanup(
            lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=route_table_id)
        )

    def _route_table_state():
        tables = ec2.describe_transit_gateway_route_tables(
            TransitGatewayRouteTableIds=[route_table_id]
        )["TransitGatewayRouteTables"]
        return tables[0]["State"] if tables else None

    _poll_until(_route_table_state, lambda s: s == "available", timeout_s=180, interval_s=5)
    return route_table_id


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={result!r})")
        time.sleep(interval_s)
        result = probe()
    return result


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected a ClientError for a nonexistent route table id, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
