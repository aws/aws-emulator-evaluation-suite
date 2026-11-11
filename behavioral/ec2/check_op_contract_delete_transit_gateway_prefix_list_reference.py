"""op-contract-deleteTransitGatewayPrefixListReference."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteTransitGatewayPrefixListReference"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTransitGatewayPrefixListReference removes a reference; bogus route table id -> NotFound."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgwplr-")

    tgw_id = _create_tgw(ctx, ec2, name)
    route_table_id = _create_route_table(ctx, ec2, tgw_id, name)
    prefix_list_id = _create_prefix_list(ctx, ec2, name)

    # A freshly created route table starts out "pending" and briefly rejects mutations
    # (e.g. CreateTransitGatewayPrefixListReference -> IncorrectState) until it settles.
    _poll(
        lambda: ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[route_table_id])[
            "TransitGatewayRouteTables"
        ][0]["State"],
        lambda s: s == "available",
        timeout_s=120.0,
    )

    created = ec2.create_transit_gateway_prefix_list_reference(
        TransitGatewayRouteTableId=route_table_id,
        PrefixListId=prefix_list_id,
        Blackhole=True,
    )
    created_rtid = created["TransitGatewayPrefixListReference"]["TransitGatewayRouteTableId"]
    assert created_rtid == route_table_id, f"expected route table {route_table_id}, got {created_rtid}"

    state = _poll(
        lambda: _reference_state(ec2, route_table_id, prefix_list_id),
        lambda s: s in ("available", "modifying"),
        timeout_s=60.0,
    )
    assert state in ("available", "modifying"), f"prefix list reference never settled (last={state})"

    delete_resp = ec2.delete_transit_gateway_prefix_list_reference(
        TransitGatewayRouteTableId=route_table_id, PrefixListId=prefix_list_id
    )
    deleted_rtid = delete_resp["TransitGatewayPrefixListReference"]["TransitGatewayRouteTableId"]
    assert deleted_rtid == route_table_id, f"expected route table {route_table_id}, got {deleted_rtid}"

    final_state = _poll(
        lambda: _reference_state(ec2, route_table_id, prefix_list_id, treat_gone_as="gone"),
        lambda s: s == "gone",
        timeout_s=60.0,
    )
    assert final_state == "gone", f"prefix list reference never disappeared (last={final_state})"

    bogus_route_table_id = "tgw-rtb-0123456789abcdef0"
    error = _error(
        lambda: ec2.delete_transit_gateway_prefix_list_reference(
            TransitGatewayRouteTableId=bogus_route_table_id, PrefixListId=prefix_list_id
        )
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


def _reference_state(ec2, route_table_id, prefix_list_id, treat_gone_as=None):
    try:
        resp = ec2.get_transit_gateway_prefix_list_references(
            TransitGatewayRouteTableId=route_table_id,
            Filters=[{"Name": "prefix-list-id", "Values": [prefix_list_id]}],
        )
        refs = resp["TransitGatewayPrefixListReferences"]
        if not refs:
            return treat_gone_as
        return refs[0]["State"]
    except ClientError as exc:
        if treat_gone_as and "NotFound" in exc.response["Error"]["Code"]:
            return treat_gone_as
        raise


def _create_tgw(ctx, ec2, name):
    created = ec2.create_transit_gateway(
        Description=name,
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    tgw_id = created["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id)))
    _poll(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=180.0,
    )
    return tgw_id


def _create_route_table(ctx, ec2, tgw_id, name):
    created = ec2.create_transit_gateway_route_table(
        TransitGatewayId=tgw_id,
        TagSpecifications=[{"ResourceType": "transit-gateway-route-table", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    route_table_id = created["TransitGatewayRouteTable"]["TransitGatewayRouteTableId"]
    ctx.on_cleanup(
        lambda: _best_effort(lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=route_table_id))
    )
    return route_table_id


def _create_prefix_list(ctx, ec2, name):
    created = ec2.create_managed_prefix_list(
        PrefixListName=name,
        MaxEntries=5,
        AddressFamily="IPv4",
        Entries=[{"Cidr": "10.214.0.0/24", "Description": "test"}],
        TagSpecifications=[{"ResourceType": "prefix-list", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    prefix_list_id = created["PrefixList"]["PrefixListId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_managed_prefix_list(PrefixListId=prefix_list_id)))
    _poll(
        lambda: ec2.describe_managed_prefix_lists(PrefixListIds=[prefix_list_id])["PrefixLists"][0]["State"],
        lambda s: s == "create-complete",
        timeout_s=60.0,
    )
    return prefix_list_id


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidPrefixListID.NotFound",
            "InvalidRouteTableID.NotFound",
            "InvalidTransitGatewayID.NotFound",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
