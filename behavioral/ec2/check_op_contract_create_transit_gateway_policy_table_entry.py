"""op-contract-create-transit-gateway-policy-table-entry."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-transit-gateway-policy-table-entry"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTransitGatewayPolicyTableEntry: success adds a rule that targets a route
    table; DryRun=True is honored (permission-checked, no mutation)."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgwpte-")
    tgw_id = _create_tgw(ctx, name)
    _wait_tgw_available(ctx, tgw_id)
    policy_table_id = _create_policy_table(ctx, tgw_id, name)
    target_rt_id = _create_route_table(ctx, tgw_id, name)

    # --- error boundary: DryRun must fail with DryRunOperation and create nothing ---
    code, message = _error_of(
        lambda: ec2.create_transit_gateway_policy_table_entry(
            TransitGatewayPolicyTableId=policy_table_id,
            PolicyRuleNumber="1",
            TargetRouteTableId=target_rt_id,
            DryRun=True,
        )
    )
    assert code == "DryRunOperation", f"unexpected code: {code}"
    assert message == "Request would have succeeded, but DryRun flag is set.", message
    entries_after_dry_run = ec2.get_transit_gateway_policy_table_entries(
        TransitGatewayPolicyTableId=policy_table_id
    )["TransitGatewayPolicyTableEntries"]
    assert entries_after_dry_run == [], "DryRun must not create a policy table entry"

    # --- success path ---
    resp = ec2.create_transit_gateway_policy_table_entry(
        TransitGatewayPolicyTableId=policy_table_id,
        PolicyRuleNumber="1",
        TargetRouteTableId=target_rt_id,
    )
    entry = resp["TransitGatewayPolicyTableEntry"]
    assert entry["PolicyRuleNumber"] == "1", f"expected rule 1, got {entry.get('PolicyRuleNumber')!r}"
    assert entry["TargetRouteTableId"] == target_rt_id, (
        f"expected target route table {target_rt_id}, got {entry.get('TargetRouteTableId')!r}"
    )
    ctx.on_cleanup(
        lambda: _delete_entry(ctx, policy_table_id, entry["PolicyRuleNumber"])
    )

    # confirm it is actually observable via the read path
    listed = ec2.get_transit_gateway_policy_table_entries(TransitGatewayPolicyTableId=policy_table_id)[
        "TransitGatewayPolicyTableEntries"
    ]
    assert any(e["PolicyRuleNumber"] == "1" and e["TargetRouteTableId"] == target_rt_id for e in listed), (
        f"created entry not observable via get_transit_gateway_policy_table_entries: {listed!r}"
    )


def _error_of(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected DryRunOperation, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 120.0, interval_s: float = 3.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_tgw(ctx, name: str) -> str:
    ec2 = ctx.client("ec2")
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


def _create_policy_table(ctx, tgw_id: str, name: str) -> str:
    ec2 = ctx.client("ec2")
    table_id = ec2.create_transit_gateway_policy_table(
        TransitGatewayId=tgw_id,
        TagSpecifications=[
            {"ResourceType": "transit-gateway-policy-table", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["TransitGatewayPolicyTable"]["TransitGatewayPolicyTableId"]
    ctx.on_cleanup(lambda: _delete_policy_table(ctx, table_id))
    _poll_until(
        lambda: ec2.describe_transit_gateway_policy_tables(TransitGatewayPolicyTableIds=[table_id])[
            "TransitGatewayPolicyTables"
        ][0]["State"],
        lambda s: s in ("available", "failed"),
        timeout_s=90.0,
    )
    return table_id


def _create_route_table(ctx, tgw_id: str, name: str) -> str:
    ec2 = ctx.client("ec2")
    rt_id = ec2.create_transit_gateway_route_table(
        TransitGatewayId=tgw_id,
        TagSpecifications=[
            {"ResourceType": "transit-gateway-route-table", "Tags": [{"Key": "Name", "Value": name}]}
        ],
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


def _delete_entry(ctx, policy_table_id: str, rule_number: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_transit_gateway_policy_table_entry(
            TransitGatewayPolicyTableId=policy_table_id, PolicyRuleNumber=rule_number
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayPolicyTableId.NotFound":
            raise


def _delete_policy_table(ctx, table_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_transit_gateway_policy_table(TransitGatewayPolicyTableId=table_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayPolicyTableId.NotFound":
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
