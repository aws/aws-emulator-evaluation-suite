"""op-contract-deleteTransitGatewayRouteTable."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteTransitGatewayRouteTable"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTransitGatewayRouteTable tears down an available route table; bogus id -> NotFound."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgwrtb-")

    tgw_id = _create_tgw(ctx, ec2, name)

    created = ec2.create_transit_gateway_route_table(
        TransitGatewayId=tgw_id,
        TagSpecifications=[{"ResourceType": "transit-gateway-route-table", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    route_table_id = created["TransitGatewayRouteTable"]["TransitGatewayRouteTableId"]
    ctx.on_cleanup(
        lambda: _best_effort(lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=route_table_id))
    )

    state = _poll(
        lambda: _rt_state(ec2, route_table_id),
        lambda s: s == "available",
        timeout_s=120.0,
    )
    assert state == "available", f"route table never became available (last={state})"

    delete_resp = ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=route_table_id)
    delete_state = delete_resp["TransitGatewayRouteTable"]["State"]
    assert delete_state in ("deleting", "deleted"), f"expected deleting/deleted, got {delete_state}"

    final_state = _poll(
        lambda: _rt_state(ec2, route_table_id, treat_notfound_as="deleted"),
        lambda s: s == "deleted",
        timeout_s=600.0,
    )
    assert final_state == "deleted", f"route table never reached deleted (last={final_state})"

    bogus_route_table_id = "tgw-rtb-0123456789abcdef0"
    error = _error(
        lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=bogus_route_table_id)
    )
    assert error["Code"] == "InvalidRouteTableID.NotFound", error
    assert error.get("Message") == f"Transit Gateway Route Table {bogus_route_table_id} was deleted or does not exist.", error


def _poll(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn() and return its botocore Error dict; a call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _rt_state(ec2, route_table_id, treat_notfound_as=None):
    try:
        resp = ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[route_table_id])
        tables = resp["TransitGatewayRouteTables"]
        if not tables:
            return treat_notfound_as
        return tables[0]["State"]
    except ClientError as exc:
        if treat_notfound_as and "NotFound" in exc.response["Error"]["Code"]:
            return treat_notfound_as
        raise


def _retry_on_tgw_limit(fn, timeout_s=600.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TransitGatewayLimitExceeded" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _create_tgw(ctx, ec2, name):
    created = _retry_on_tgw_limit(
        lambda: ec2.create_transit_gateway(
            Description=name,
            TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
        )
    )
    tgw_id = created["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id)))
    _poll(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=600.0,
    )
    return tgw_id


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidRouteTableID.NotFound",
            "InvalidTransitGatewayID.NotFound",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
