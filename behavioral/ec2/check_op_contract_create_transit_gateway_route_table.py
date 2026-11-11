"""op-contract-create-transit-gateway-route-table."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-transit-gateway-route-table"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTransitGatewayRouteTable: success creates a route table bound to the transit
    gateway and reaches 'available'; a nonexistent transit gateway id is rejected."""
    ec2 = ctx.client("ec2")
    tgw_id = _create_tgw(ctx)
    _wait_tgw_available(ctx, tgw_id)

    # --- error boundary: transit gateway that doesn't exist ---
    code, message = _error_of(
        lambda: ec2.create_transit_gateway_route_table(TransitGatewayId="tgw-00000000000000000")
    )
    assert code == "InvalidTransitGatewayID.NotFound", f"unexpected code: {code}"
    assert message == "Transit Gateway tgw-00000000000000000 was deleted or does not exist.", message

    # --- success path ---
    resp = ec2.create_transit_gateway_route_table(TransitGatewayId=tgw_id)
    rt = resp["TransitGatewayRouteTable"]
    rt_id = rt["TransitGatewayRouteTableId"]
    ctx.on_cleanup(lambda: _delete_route_table(ctx, rt_id))
    assert rt["TransitGatewayId"] == tgw_id, f"expected TransitGatewayId {tgw_id!r}, got {rt['TransitGatewayId']!r}"
    assert rt["State"] in ("pending", "available"), f"expected pending/available, got {rt['State']!r}"
    assert rt["DefaultAssociationRouteTable"] is False, f"expected DefaultAssociationRouteTable False, got {rt['DefaultAssociationRouteTable']!r}"
    assert rt["DefaultPropagationRouteTable"] is False, f"expected DefaultPropagationRouteTable False, got {rt['DefaultPropagationRouteTable']!r}"

    final_state = _poll_until(
        lambda: ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[rt_id])[
            "TransitGatewayRouteTables"
        ][0]["State"],
        lambda s: s in ("available", "failed"),
        timeout_s=90.0,
    )
    assert final_state == "available", f"route table ended in {final_state}"


def _error_of(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    emulator accepting input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 120.0, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_tgw(ctx) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgw-")
    resp = ec2.create_transit_gateway(
        Description=name,
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    tgw_id = resp["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _delete_tgw(ctx, tgw_id))
    return tgw_id


def _wait_tgw_available(ctx, tgw_id: str) -> None:
    ec2 = ctx.client("ec2")
    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=180.0,
    )


def _delete_route_table(ctx, rt_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=rt_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidRouteTableID.NotFound":
            raise


def _delete_tgw(ctx, tgw_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayID.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
