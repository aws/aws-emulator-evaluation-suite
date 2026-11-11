"""transit-gateway-policy-table-entry-crud-consistency."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "transit-gateway-policy-table-entry-crud-consistency"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created TGW policy table entry is retrievable with the same match criteria and removed after delete."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgw-")
    tgw_id = ec2.create_transit_gateway(
        Description=name,
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id))
    _wait_tgw_available(ec2, tgw_id)

    route_table_id = ec2.create_transit_gateway_route_table(
        TransitGatewayId=tgw_id,
        TagSpecifications=[
            {"ResourceType": "transit-gateway-route-table", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["TransitGatewayRouteTable"]["TransitGatewayRouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=route_table_id))
    _wait_route_table_available(ec2, route_table_id)

    policy_table_id = ec2.create_transit_gateway_policy_table(
        TransitGatewayId=tgw_id,
        TagSpecifications=[
            {"ResourceType": "transit-gateway-policy-table", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["TransitGatewayPolicyTable"]["TransitGatewayPolicyTableId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway_policy_table(TransitGatewayPolicyTableId=policy_table_id))
    _wait_policy_table_available(ec2, policy_table_id)

    entry = ec2.create_transit_gateway_policy_table_entry(
        TransitGatewayPolicyTableId=policy_table_id,
        PolicyRuleNumber="1",
        PolicyRule={
            "SourceCidrBlock": "10.50.0.0/16",
            "SourcePortRange": "*",
            "DestinationCidrBlock": "10.51.0.0/16",
            "DestinationPortRange": "*",
            "Protocol": "*",
        },
        TargetRouteTableId=route_table_id,
    )["TransitGatewayPolicyTableEntry"]
    assert entry["PolicyRuleNumber"] == "1"
    assert entry["TargetRouteTableId"] == route_table_id

    found = _find_entry(ec2, policy_table_id, "1")
    assert found is not None, "policy table entry not visible immediately after creation"
    assert found["TargetRouteTableId"] == route_table_id
    assert found["PolicyRule"]["SourceCidrBlock"] == "10.50.0.0/16"
    assert found["PolicyRule"]["DestinationCidrBlock"] == "10.51.0.0/16"

    ec2.delete_transit_gateway_policy_table_entry(TransitGatewayPolicyTableId=policy_table_id, PolicyRuleNumber="1")

    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        remaining = _find_entry(ec2, policy_table_id, "1")
        if remaining is None or remaining.get("State") == "deleted":
            return
        time.sleep(3)
    raise AssertionError("deleted policy table entry is still listed as active")


def _wait_tgw_available(ec2, tgw_id, timeout_s=300.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        tgw = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]
        if tgw["State"] == "available":
            return
        if tgw["State"] in ("deleting", "deleted"):
            raise AssertionError(f"transit gateway entered unexpected state {tgw['State']}")
        time.sleep(2)
    raise AssertionError("transit gateway never became available")


def _wait_route_table_available(ec2, route_table_id, timeout_s=120.0):
    # A route table that just reported "available" from CreateTransitGatewayRouteTable's own
    # response can still briefly be rejected as a policy-table-entry target with IncorrectState
    # while the backend finishes propagating that state internally.
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        rt = ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[route_table_id])[
            "TransitGatewayRouteTables"
        ][0]
        if rt["State"] == "available":
            return
        if rt["State"] in ("deleting", "deleted"):
            raise AssertionError(f"transit gateway route table entered unexpected state {rt['State']}")
        time.sleep(5)
    raise AssertionError("transit gateway route table never became available")


def _wait_policy_table_available(ec2, policy_table_id, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        pt = ec2.describe_transit_gateway_policy_tables(TransitGatewayPolicyTableIds=[policy_table_id])[
            "TransitGatewayPolicyTables"
        ][0]
        if pt["State"] == "available":
            return
        if pt["State"] in ("deleting", "deleted"):
            raise AssertionError(f"transit gateway policy table entered unexpected state {pt['State']}")
        time.sleep(5)
    raise AssertionError("transit gateway policy table never became available")


def _find_entry(ec2, policy_table_id, rule_number):
    resp = ec2.get_transit_gateway_policy_table_entries(TransitGatewayPolicyTableId=policy_table_id)
    for e in resp.get("TransitGatewayPolicyTableEntries", []):
        if e["PolicyRuleNumber"] == rule_number:
            return e
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
