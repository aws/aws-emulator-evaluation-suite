"""op-contract-create-transit-gateway-prefix-list-reference."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-transit-gateway-prefix-list-reference"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTransitGatewayPrefixListReference: success creates a blackhole reference to
    a managed prefix list in a transit gateway route table; a nonexistent prefix list id
    is rejected with the specific NotFound error."""
    ec2 = ctx.client("ec2")
    tgw_id = _create_tgw(ctx)
    _wait_tgw_available(ctx, tgw_id)
    rt_id = _create_route_table(ctx, tgw_id)
    prefix_list_id = _create_prefix_list(ctx)

    # --- error boundary: prefix list that doesn't exist ---
    code, message = _error_of(
        lambda: ec2.create_transit_gateway_prefix_list_reference(
            TransitGatewayRouteTableId=rt_id,
            PrefixListId="pl-00000000000000000",
            Blackhole=True,
        )
    )
    assert code == "InvalidPrefixListID.NotFound", f"unexpected code: {code}"
    assert message == "The prefix list (pl-00000000000000000) does not exist.", message

    # --- success path ---
    resp = ec2.create_transit_gateway_prefix_list_reference(
        TransitGatewayRouteTableId=rt_id,
        PrefixListId=prefix_list_id,
        Blackhole=True,
    )
    ref = resp["TransitGatewayPrefixListReference"]
    ctx.on_cleanup(lambda: _delete_reference(ctx, rt_id, prefix_list_id))
    assert ref["PrefixListId"] == prefix_list_id
    assert ref["TransitGatewayRouteTableId"] == rt_id
    assert ref["Blackhole"] is True
    assert ref["State"] in ("pending", "available"), ref["State"]

    final_state = _poll_until(
        lambda: _describe_reference(ctx, rt_id, prefix_list_id)["State"],
        lambda s: s in ("available", "failed"),
        timeout_s=90.0,
    )
    assert final_state == "available", f"prefix list reference ended in {final_state}"


def _error_of(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError("the call real AWS rejects was accepted")


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


def _create_route_table(ctx, tgw_id: str) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgw-rt-")
    rt_id = ec2.create_transit_gateway_route_table(
        TransitGatewayId=tgw_id,
        TagSpecifications=[{"ResourceType": "transit-gateway-route-table", "Tags": [{"Key": "Name", "Value": name}]}],
    )["TransitGatewayRouteTable"]["TransitGatewayRouteTableId"]
    ctx.on_cleanup(lambda: _delete_route_table(ctx, rt_id))
    _poll_until(
        lambda: ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[rt_id])[
            "TransitGatewayRouteTables"
        ][0]["State"],
        lambda s: s in ("available", "failed"),
        timeout_s=90.0,
    )
    return rt_id


def _create_prefix_list(ctx) -> str:
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-pl-")
    pl_id = ec2.create_managed_prefix_list(
        PrefixListName=name,
        MaxEntries=1,
        AddressFamily="IPv4",
        Entries=[{"Cidr": "10.99.0.0/24", "Description": "sim2real"}],
        TagSpecifications=[{"ResourceType": "prefix-list", "Tags": [{"Key": "Name", "Value": name}]}],
    )["PrefixList"]["PrefixListId"]
    ctx.on_cleanup(lambda: _delete_prefix_list(ctx, pl_id))
    _poll_until(
        lambda: ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"][0]["State"],
        lambda s: s in ("create-complete", "create-failed"),
        timeout_s=60.0,
    )
    return pl_id


def _describe_reference(ctx, rt_id: str, pl_id: str) -> dict:
    ec2 = ctx.client("ec2")
    resp = ec2.get_transit_gateway_prefix_list_references(
        TransitGatewayRouteTableId=rt_id,
        Filters=[{"Name": "prefix-list-id", "Values": [pl_id]}],
    )
    return resp["TransitGatewayPrefixListReferences"][0]


def _delete_reference(ctx, rt_id: str, pl_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_transit_gateway_prefix_list_reference(TransitGatewayRouteTableId=rt_id, PrefixListId=pl_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidRouteTableID.NotFound":
            raise


def _delete_prefix_list(ctx, pl_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_managed_prefix_list(PrefixListId=pl_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidPrefixListID.NotFound":
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
