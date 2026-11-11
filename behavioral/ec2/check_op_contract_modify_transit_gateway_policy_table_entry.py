"""op-contract-modify-transit-gateway-policy-table-entry."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-modify-transit-gateway-policy-table-entry"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyTransitGatewayPolicyTableEntry retargets rule 1 to a second route table, echoed and read
    back; a fabricated policy table id fails with InvalidTransitGatewayPolicyTableId.Malformed."""
    ec2 = ctx.client("ec2")
    for op in (
        "create_transit_gateway_policy_table",
        "create_transit_gateway_policy_table_entry",
        "modify_transit_gateway_policy_table_entry",
        "delete_transit_gateway_policy_table_entry",
        "delete_transit_gateway_policy_table",
    ):
        if not hasattr(ec2, op):
            raise AssertionError(f"unreachable: ec2 client lacks {op} (older botocore)")

    name = ctx.unique_name("sim2real-tgw-")
    tgw_id = ec2.create_transit_gateway(
        Description=name,
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id))
    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0],
        lambda t: t["State"] == "available",
        timeout_s=240,
    )

    rt1_id = _retry_on_incorrect_state(
        lambda: ec2.create_transit_gateway_route_table(
            TransitGatewayId=tgw_id,
            TagSpecifications=[
                {"ResourceType": "transit-gateway-route-table", "Tags": [{"Key": "Name", "Value": name}]}
            ],
        )
    )["TransitGatewayRouteTable"]["TransitGatewayRouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=rt1_id))
    rt2_id = _retry_on_incorrect_state(
        lambda: ec2.create_transit_gateway_route_table(
            TransitGatewayId=tgw_id,
            TagSpecifications=[
                {"ResourceType": "transit-gateway-route-table", "Tags": [{"Key": "Name", "Value": name}]}
            ],
        )
    )["TransitGatewayRouteTable"]["TransitGatewayRouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=rt2_id))
    for rt_id in (rt1_id, rt2_id):
        _poll_until(
            lambda rt_id=rt_id: ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[rt_id])[
                "TransitGatewayRouteTables"
            ][0],
            lambda t: t["State"] == "available",
            timeout_s=120,
        )

    pt_id = _retry_on_incorrect_state(
        lambda: ec2.create_transit_gateway_policy_table(
            TransitGatewayId=tgw_id,
            TagSpecifications=[
                {"ResourceType": "transit-gateway-policy-table", "Tags": [{"Key": "Name", "Value": name}]}
            ],
        )
    )["TransitGatewayPolicyTable"][
        "TransitGatewayPolicyTableId"
    ]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway_policy_table(TransitGatewayPolicyTableId=pt_id))
    _poll_until(
        lambda: ec2.describe_transit_gateway_policy_tables(TransitGatewayPolicyTableIds=[pt_id])[
            "TransitGatewayPolicyTables"
        ][0],
        lambda t: t["State"] == "available",
        timeout_s=120,
    )

    ec2.create_transit_gateway_policy_table_entry(
        TransitGatewayPolicyTableId=pt_id, PolicyRuleNumber="1", TargetRouteTableId=rt1_id
    )
    ctx.on_cleanup(
        lambda: ec2.delete_transit_gateway_policy_table_entry(
            TransitGatewayPolicyTableId=pt_id, PolicyRuleNumber="1"
        )
    )

    resp = ec2.modify_transit_gateway_policy_table_entry(
        TransitGatewayPolicyTableId=pt_id, PolicyRuleNumber="1", TargetRouteTableId=rt2_id
    )
    entry = resp["TransitGatewayPolicyTableEntry"]
    assert entry["TargetRouteTableId"] == rt2_id, entry
    assert entry["PolicyRuleNumber"] == "1", entry

    # independent read at the destination: the mutating call's own response is not
    # proof the retarget stuck, so re-fetch the entry through a different operation.
    listed = ec2.get_transit_gateway_policy_table_entries(TransitGatewayPolicyTableId=pt_id)[
        "TransitGatewayPolicyTableEntries"
    ]
    listed_entry = next((e for e in listed if e.get("PolicyRuleNumber") == "1"), None)
    assert listed_entry is not None, listed
    assert listed_entry["TargetRouteTableId"] == rt2_id, listed_entry

    code, _ = _client_error(
        lambda: ec2.modify_transit_gateway_policy_table_entry(
            TransitGatewayPolicyTableId="tgw-ptable-00000000000000000",
            PolicyRuleNumber="1",
            TargetRouteTableId=rt1_id,
        )
    )
    # A well-formed-but-fabricated policy table ID fails AWS's ID validation
    # before it ever gets to an existence check, so the API returns
    # .Malformed rather than .NotFound.
    assert code == "InvalidTransitGatewayPolicyTableId.Malformed", f"unexpected error code: {code}"


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _retry_on_incorrect_state(fn, timeout_s=180.0, interval_s=10.0):
    """A transit gateway that just reported describe-state "available" can still briefly
    reject a dependent create (e.g. CreateTransitGatewayRouteTable) with IncorrectState
    while the backend finishes propagating that state internally."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "IncorrectState":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
