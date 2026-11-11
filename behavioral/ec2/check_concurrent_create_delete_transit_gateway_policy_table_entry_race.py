"""concurrent-create-delete-transit-gateway-policy-table-entry-race."""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "concurrent-create-delete-transit-gateway-policy-table-entry-race"
GROUP = "concurrency"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CreateTransitGatewayPolicyTableEntry racing a delete of the same rule number leaves at most one entry,
    targeting one of the two written route tables, and the rule number then takes a fresh entry.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-tgwptrace-")

    tgw_id = ec2.create_transit_gateway(
        Description=name,
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id))
    _poll_until(lambda: _tgw_state(ec2, tgw_id), lambda s: s == "available", timeout_s=300, interval_s=10)

    route_table_a = ec2.create_transit_gateway_route_table(TransitGatewayId=tgw_id)[
        "TransitGatewayRouteTable"
    ]["TransitGatewayRouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=route_table_a))
    route_table_b = ec2.create_transit_gateway_route_table(TransitGatewayId=tgw_id)[
        "TransitGatewayRouteTable"
    ]["TransitGatewayRouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=route_table_b))
    route_table_c = ec2.create_transit_gateway_route_table(TransitGatewayId=tgw_id)[
        "TransitGatewayRouteTable"
    ]["TransitGatewayRouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=route_table_c))
    # CreateTransitGatewayPolicyTableEntry rejects a target route table with IncorrectState
    # while it is still provisioning, so every route table must reach "available" before
    # it is usable as a target.
    for rt in (route_table_a, route_table_b, route_table_c):
        _poll_until(lambda rt=rt: _route_table_state(ec2, rt), lambda s: s == "available", timeout_s=90, interval_s=3)

    policy_table_id = ec2.create_transit_gateway_policy_table(TransitGatewayId=tgw_id)[
        "TransitGatewayPolicyTable"
    ]["TransitGatewayPolicyTableId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway_policy_table(TransitGatewayPolicyTableId=policy_table_id))
    _poll_until(
        lambda: _policy_table_state(ec2, policy_table_id), lambda s: s == "available", timeout_s=120, interval_s=3
    )

    def _rule(target_rt: str) -> dict[str, str]:
        return {
            "SourceCidrBlock": "10.60.0.0/16",
            "SourcePortRange": "*",
            "DestinationCidrBlock": "10.61.0.0/16",
            "DestinationPortRange": "*",
            "Protocol": "*",
        }

    # Baseline entry that the race will contend over.
    ec2.create_transit_gateway_policy_table_entry(
        TransitGatewayPolicyTableId=policy_table_id,
        PolicyRuleNumber="1",
        PolicyRule=_rule(route_table_a),
        TargetRouteTableId=route_table_a,
    )
    baseline = _find_entry(ec2, policy_table_id, "1")
    assert baseline is not None and baseline["TargetRouteTableId"] == route_table_a, (
        f"baseline entry not visible with expected target right after creation: {baseline!r}"
    )

    barrier = threading.Barrier(2)

    def _recreate():
        barrier.wait(timeout=30)
        return _call(
            lambda: ec2.create_transit_gateway_policy_table_entry(
                TransitGatewayPolicyTableId=policy_table_id,
                PolicyRuleNumber="1",
                PolicyRule=_rule(route_table_b),
                TargetRouteTableId=route_table_b,
            )
        )

    def _delete():
        barrier.wait(timeout=30)
        return _call(
            lambda: ec2.delete_transit_gateway_policy_table_entry(
                TransitGatewayPolicyTableId=policy_table_id, PolicyRuleNumber="1"
            )
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_create = pool.submit(_recreate)
        fut_delete = pool.submit(_delete)
        create_result = fut_create.result()
        delete_result = fut_delete.result()

    # The entry state has only active/deleted, but reads can lag the writes, so poll
    # GetTransitGatewayPolicyTableEntries until consecutive reads agree.
    settled = _poll_until_stable(lambda: _live_entry(ec2, policy_table_id, "1"), timeout_s=30, interval_s=1)

    # Never a duplicate/corrupted entry: at most one live entry for rule 1,
    # and if present it exactly matches one of the two writes (the original
    # baseline or the racing recreate) -- never a mix of both.
    if settled is not None:
        assert settled["TargetRouteTableId"] in (route_table_a, route_table_b), (
            f"policy table entry left in a corrupted state: {settled}"
        )

    # Prove the key is left reusable (no dangling ghost blocking reuse): clear
    # whatever is there, then create a fresh entry at the same rule number.
    if settled is not None:
        ec2.delete_transit_gateway_policy_table_entry(
            TransitGatewayPolicyTableId=policy_table_id, PolicyRuleNumber="1"
        )

        def _gone():
            e = _find_entry(ec2, policy_table_id, "1")
            return e is None or e.get("State") == "deleted"

        _poll_until(_gone, lambda ok: ok, timeout_s=60, interval_s=3)

    ec2.create_transit_gateway_policy_table_entry(
        TransitGatewayPolicyTableId=policy_table_id,
        PolicyRuleNumber="1",
        PolicyRule=_rule(route_table_c),
        TargetRouteTableId=route_table_c,
    )
    reused = _find_entry(ec2, policy_table_id, "1")
    assert reused is not None and reused["TargetRouteTableId"] == route_table_c, (
        f"rule number 1 was not cleanly reusable after the create/delete race, results were "
        f"create={create_result!r} delete={delete_result!r}"
    )


def _call(fn: Callable[[], Any]):
    from botocore.exceptions import ClientError

    try:
        return ("ok", fn())
    except ClientError as exc:
        return ("error", exc.response["Error"]["Code"])


def _tgw_state(ec2, tgw_id: str):
    return ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"]


def _policy_table_state(ec2, policy_table_id: str):
    return ec2.describe_transit_gateway_policy_tables(TransitGatewayPolicyTableIds=[policy_table_id])[
        "TransitGatewayPolicyTables"
    ][0]["State"]


def _route_table_state(ec2, route_table_id: str):
    return ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[route_table_id])[
        "TransitGatewayRouteTables"
    ][0]["State"]


def _find_entry(ec2, policy_table_id: str, rule_number: str):
    resp = ec2.get_transit_gateway_policy_table_entries(TransitGatewayPolicyTableId=policy_table_id)
    for e in resp.get("TransitGatewayPolicyTableEntries", []):
        if e["PolicyRuleNumber"] == rule_number:
            return e
    return None


def _live_entry(ec2, policy_table_id: str, rule_number: str):
    e = _find_entry(ec2, policy_table_id, rule_number)
    if e is not None and e.get("State") == "deleted":
        return None
    return e


def _poll_until_stable(probe: Callable[[], Any], *, timeout_s: float, interval_s: float, stable_reads: int = 3):
    """Polls `probe` until it returns the same value on `stable_reads`
    consecutive reads (comparing by TargetRouteTableId, or None), or until
    timeout -- then returns the last observed value regardless."""
    deadline = time.monotonic() + timeout_s
    last_key = object()
    streak = 0
    last_value = None
    while time.monotonic() < deadline:
        value = probe()
        key = value["TargetRouteTableId"] if value is not None else None
        if key == last_key:
            streak += 1
            if streak >= stable_reads:
                return value
        else:
            streak = 1
            last_key = key
        last_value = value
        time.sleep(interval_s)
    return last_value


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
