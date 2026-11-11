"""op-contract-get-transit-gateway-prefix-list-references."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-transit-gateway-prefix-list-references"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTransitGatewayPrefixListReferences: empty list for a fresh route table, NotFound for a bogus id."""
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-tgw-")
    tgw_resp = ec2.create_transit_gateway(
        Description=name,
        Options={
            "AutoAcceptSharedAttachments": "disable",
            "DefaultRouteTableAssociation": "enable",
            "DefaultRouteTablePropagation": "enable",
        },
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
    )["TransitGateway"]
    tgw_id = tgw_resp["TransitGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id))
    route_table_id = tgw_resp["Options"]["AssociationDefaultRouteTableId"]

    def _tgw_state():
        tgws = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"]
        return tgws[0]["State"] if tgws else None

    _poll_until(_tgw_state, lambda s: s == "available", timeout_s=180, interval_s=5)

    def _route_table_state():
        tables = ec2.describe_transit_gateway_route_tables(
            TransitGatewayRouteTableIds=[route_table_id]
        )["TransitGatewayRouteTables"]
        return tables[0]["State"] if tables else None

    _poll_until(_route_table_state, lambda s: s == "available", timeout_s=180, interval_s=5)

    resp = ec2.get_transit_gateway_prefix_list_references(TransitGatewayRouteTableId=route_table_id)
    assert "TransitGatewayPrefixListReferences" in resp, f"missing key in response: {resp!r}"
    assert resp["TransitGatewayPrefixListReferences"] == [], (
        "a fresh transit gateway route table should have no prefix list references"
    )

    bogus_id = "tgw-rtb-00000000000000000"
    code, message = _error(
        lambda: ec2.get_transit_gateway_prefix_list_references(TransitGatewayRouteTableId=bogus_id)
    )
    assert code == "InvalidRouteTableID.NotFound", f"unexpected error code {code!r}"
    expected = f"Transit Gateway Route Table {bogus_id} was deleted or does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={result!r})")
        time.sleep(interval_s)
        result = probe()
    return result


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises
    AssertionError: a target that accepts what AWS refuses fails loudly here."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
