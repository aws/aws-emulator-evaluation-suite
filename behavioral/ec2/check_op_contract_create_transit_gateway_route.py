"""op-contract-create-transit-gateway-route."""
from __future__ import annotations

import time
from typing import Any, Callable, Optional

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-transit-gateway-route"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTransitGatewayRoute: success installs a static blackhole route that is
    observable via search_transit_gateway_routes; DryRun=True is honored."""
    ec2 = ctx.client("ec2")
    tgw_id = _create_tgw(ctx)
    _wait_tgw_available(ctx, tgw_id)
    rt_id = _create_route_table(ctx, tgw_id)
    cidr = "10.88.0.0/24"

    # --- error boundary: DryRun must fail with DryRunOperation and create nothing ---
    code, message = _error(
        lambda: _retry_on_incorrect_state(
            lambda: ec2.create_transit_gateway_route(
                TransitGatewayRouteTableId=rt_id,
                DestinationCidrBlock=cidr,
                Blackhole=True,
                DryRun=True,
            )
        )
    )
    assert code == "DryRunOperation", f"unexpected code: {code}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"
    before = ec2.search_transit_gateway_routes(
        TransitGatewayRouteTableId=rt_id,
        Filters=[{"Name": "route-search.exact-match", "Values": [cidr]}],
    )["Routes"]
    assert before == [], "DryRun must not create a route"

    # --- success path ---
    resp = _retry_on_incorrect_state(
        lambda: ec2.create_transit_gateway_route(
            TransitGatewayRouteTableId=rt_id, DestinationCidrBlock=cidr, Blackhole=True
        )
    )
    route = resp["Route"]
    ctx.on_cleanup(lambda: _delete_route(ctx, rt_id, cidr))
    assert route["DestinationCidrBlock"] == cidr, f"expected {cidr}, got {route['DestinationCidrBlock']}"
    assert route["Type"] == "static", f"expected static, got {route['Type']}"
    assert route["State"] in ("pending", "active", "blackhole"), route["State"]

    def _route_state():
        routes = ec2.search_transit_gateway_routes(
            TransitGatewayRouteTableId=rt_id,
            Filters=[{"Name": "route-search.exact-match", "Values": [cidr]}],
        )["Routes"]
        # the route can take a moment to become visible via search after creation
        return routes[0]["State"] if routes else None

    final_state = _poll_until(
        _route_state,
        lambda s: s in ("active", "blackhole", "failed"),
        timeout_s=90.0,
    )
    assert final_state == "blackhole", f"route ended in {final_state}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 120.0, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _retry_on_incorrect_state(fn: Callable[[], Any], *, timeout_s: float = 60.0, interval_s: float = 5.0) -> Any:
    """A transit gateway route table that just reported describe-state "available" can
    still briefly reject CreateTransitGatewayRoute with IncorrectState while the backend
    finishes propagating that state internally. Poll through that narrow window instead
    of treating it as fatal."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc: Optional[BaseException] = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "IncorrectState":
                raise
            last_exc = exc
            time.sleep(interval_s)
    assert last_exc is not None
    raise last_exc


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


def _create_route_table(ctx, tgw_id: str) -> str:
    ec2 = ctx.client("ec2")
    rt_id = ec2.create_transit_gateway_route_table(TransitGatewayId=tgw_id)["TransitGatewayRouteTable"][
        "TransitGatewayRouteTableId"
    ]
    ctx.on_cleanup(lambda: _delete_route_table(ctx, rt_id))
    _poll_until(
        lambda: ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[rt_id])[
            "TransitGatewayRouteTables"
        ][0]["State"],
        lambda s: s in ("available", "failed"),
        timeout_s=90.0,
    )
    return rt_id


def _delete_route(ctx, rt_id: str, cidr: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_transit_gateway_route(TransitGatewayRouteTableId=rt_id, DestinationCidrBlock=cidr)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidRouteTableID.NotFound":
            raise


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
