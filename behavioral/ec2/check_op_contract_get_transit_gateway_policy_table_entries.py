"""op-contract-get-transit-gateway-policy-table-entries."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-transit-gateway-policy-table-entries"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetTransitGatewayPolicyTableEntries: empty entries for a fresh table, NotFound for a bogus id."""
    ec2 = ctx.client("ec2")

    tgw_name = ctx.unique_name("sim2real-tgw-")
    tgw_id = ec2.create_transit_gateway(
        Description=tgw_name,
        Options={
            "AutoAcceptSharedAttachments": "disable",
            "DefaultRouteTableAssociation": "enable",
            "DefaultRouteTablePropagation": "enable",
        },
        TagSpecifications=[
            {"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": tgw_name}]}
        ],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id))

    def _tgw_state():
        tgws = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"]
        return tgws[0]["State"] if tgws else None

    _poll_until(_tgw_state, lambda s: s == "available", timeout_s=180, interval_s=5)

    policy_table_name = ctx.unique_name("sim2real-tgwpt-")
    policy_table_id = ec2.create_transit_gateway_policy_table(
        TransitGatewayId=tgw_id,
        TagSpecifications=[
            {
                "ResourceType": "transit-gateway-policy-table",
                "Tags": [{"Key": "Name", "Value": policy_table_name}],
            }
        ],
    )["TransitGatewayPolicyTable"]["TransitGatewayPolicyTableId"]
    ctx.on_cleanup(
        lambda: ec2.delete_transit_gateway_policy_table(TransitGatewayPolicyTableId=policy_table_id)
    )

    def _state():
        tables = ec2.describe_transit_gateway_policy_tables(
            TransitGatewayPolicyTableIds=[policy_table_id]
        )["TransitGatewayPolicyTables"]
        return tables[0]["State"] if tables else None

    _poll_until(_state, lambda s: s == "available", timeout_s=90, interval_s=3)

    resp = ec2.get_transit_gateway_policy_table_entries(TransitGatewayPolicyTableId=policy_table_id)
    assert "TransitGatewayPolicyTableEntries" in resp, (
        f"expected a TransitGatewayPolicyTableEntries key in the response, got keys {sorted(resp)!r}"
    )
    assert resp["TransitGatewayPolicyTableEntries"] == [], (
        "a freshly created policy table should have no entries"
    )

    bogus_id = "tgw-ptb-00000000000000000"
    code, message = _error(
        lambda: ec2.get_transit_gateway_policy_table_entries(TransitGatewayPolicyTableId=bogus_id)
    )
    assert code == "InvalidTransitGatewayPolicyTableId.NotFound", f"unexpected error code {code!r}"
    expected = f"Transit Gateway Policy Table {bogus_id} was deleted or does not exist."
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
