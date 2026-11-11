"""op-contract-search-transit-gateway-routes."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-search-transit-gateway-routes"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SearchTransitGatewayRoutes returns a static blackhole route by state filter; an unknown route
    table fails with InvalidRouteTableID.NotFound and its exact message."""
    ec2 = ctx.client("ec2")

    tgw_id = ec2.create_transit_gateway(
        Description=ctx.unique_name("sim2real-behav-tgw-"),
        TagSpecifications=[
            {
                "ResourceType": "transit-gateway",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-tgw-")}],
            }
        ],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _wait_tgw_deleted(ctx, tgw_id))
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id))
    _wait_tgw_state(ctx, tgw_id, {"available"})

    rt_id = ec2.create_transit_gateway_route_table(TransitGatewayId=tgw_id)[
        "TransitGatewayRouteTable"
    ]["TransitGatewayRouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=rt_id))
    _wait_route_table_state(ctx, rt_id, {"available"})

    destination_cidr = "10.99.77.0/24"
    ec2.create_transit_gateway_route(
        TransitGatewayRouteTableId=rt_id,
        DestinationCidrBlock=destination_cidr,
        Blackhole=True,
    )

    # success path: search must find the blackhole route we just created
    found = None
    for _ in range(20):
        resp = ec2.search_transit_gateway_routes(
            TransitGatewayRouteTableId=rt_id,
            Filters=[{"Name": "state", "Values": ["blackhole"]}],
        )
        for route in resp.get("Routes", []):
            if route.get("DestinationCidrBlock") == destination_cidr:
                found = route
                break
        if found:
            break
        time.sleep(2)
    assert found is not None, "expected the blackhole route to be searchable"
    assert found["Type"] == "static", f"expected a static route, got Type={found['Type']!r}"
    assert found["State"] == "blackhole", f"expected State=blackhole, got {found['State']!r}"

    # error boundary: nonexistent route table id
    code, message = _error(
        lambda: ec2.search_transit_gateway_routes(
            TransitGatewayRouteTableId="tgw-rtb-00000000000000000",
            Filters=[{"Name": "state", "Values": ["active"]}],
        )
    )
    assert code == "InvalidRouteTableID.NotFound", (
        f"expected InvalidRouteTableID.NotFound for a nonexistent transit gateway route table, got {code!r}"
    )
    assert message == (
        "Transit Gateway Route Table tgw-rtb-00000000000000000 was deleted or does not exist."
    ), message


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises, because a target that accepts input real AWS refuses is a stronger signal than any code
    mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected with a NotFound error, but it succeeded and returned {result!r}"
    )


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _wait_tgw_state(ctx, tgw_id, states, timeout_s=420.0):
    ec2 = ctx.client("ec2")

    def probe():
        resp = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])
        return resp["TransitGateways"][0]["State"]

    return _poll_until(probe, lambda s: s in states, timeout_s=timeout_s)


def _wait_route_table_state(ctx, rt_id, states, timeout_s=180.0):
    ec2 = ctx.client("ec2")

    def probe():
        resp = ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[rt_id])
        return resp["TransitGatewayRouteTables"][0]["State"]

    return _poll_until(probe, lambda s: s in states, timeout_s=timeout_s)


def _wait_tgw_deleted(ctx, tgw_id, timeout_s=1.0):
    # best-effort no-op placeholder to keep cleanup ordering simple; deletion is async on AWS.
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
