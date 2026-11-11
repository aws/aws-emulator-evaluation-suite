"""op-contract-deleteTransitGatewayPolicyTableEntry."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteTransitGatewayPolicyTableEntry"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTransitGatewayPolicyTableEntry removes an entry from a policy table; bogus table id -> NotFound."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgwpte-")

    tgw_id = _create_tgw(ctx, ec2, name)

    table_created = ec2.create_transit_gateway_policy_table(
        TransitGatewayId=tgw_id,
        TagSpecifications=[
            {"ResourceType": "transit-gateway-policy-table", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )
    table_id = table_created["TransitGatewayPolicyTable"]["TransitGatewayPolicyTableId"]
    ctx.on_cleanup(
        lambda: _best_effort(lambda: ec2.delete_transit_gateway_policy_table(TransitGatewayPolicyTableId=table_id))
    )
    _poll(lambda: _table_state(ec2, table_id), lambda s: s == "available", timeout_s=120.0)

    route_table_created = _retry_on_incorrect_state(
        lambda: ec2.create_transit_gateway_route_table(
            TransitGatewayId=tgw_id,
            TagSpecifications=[
                {"ResourceType": "transit-gateway-route-table", "Tags": [{"Key": "Name", "Value": name}]}
            ],
        )
    )
    route_table_id = route_table_created["TransitGatewayRouteTable"]["TransitGatewayRouteTableId"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=route_table_id)
        )
    )
    # A route table that just reported "available" from CreateTransitGatewayRouteTable's
    # own response (or a quick describe) can still briefly be rejected as a policy-table-entry
    # target with IncorrectState while the backend finishes propagating that state
    # internally -- poll describe until it settles before referencing it.
    _poll(lambda: _route_table_state(ec2, route_table_id), lambda s: s == "available", timeout_s=120.0)

    _retry_on_incorrect_state(
        lambda: ec2.create_transit_gateway_policy_table_entry(
            TransitGatewayPolicyTableId=table_id,
            PolicyRuleNumber="1",
            TargetRouteTableId=route_table_id,
        )
    )

    entries_before = ec2.get_transit_gateway_policy_table_entries(TransitGatewayPolicyTableId=table_id)[
        "TransitGatewayPolicyTableEntries"
    ]
    assert any(e["PolicyRule"] for e in entries_before if e.get("PolicyRuleNumber") == "1"), entries_before

    ec2.delete_transit_gateway_policy_table_entry(TransitGatewayPolicyTableId=table_id, PolicyRuleNumber="1")

    entries_after = ec2.get_transit_gateway_policy_table_entries(TransitGatewayPolicyTableId=table_id)[
        "TransitGatewayPolicyTableEntries"
    ]
    assert not any(e.get("PolicyRuleNumber") == "1" for e in entries_after), entries_after

    bogus_table_id = _bogus_id_like(table_id)
    error = _error(
        lambda: ec2.delete_transit_gateway_policy_table_entry(
            TransitGatewayPolicyTableId=bogus_table_id, PolicyRuleNumber="1"
        )
    )
    assert error["Code"] == "InvalidTransitGatewayPolicyTableId.NotFound", error
    assert error.get("Message") == f"The transit-gateway-policy-table ID '{bogus_table_id}' does not exist", error


def _bogus_id_like(real_id):
    prefix, _, suffix = real_id.rpartition("-")
    return f"{prefix}-{'f' * len(suffix)}"

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


def _retry_on_incorrect_state(fn, timeout_s=180.0, interval_s=10.0):
    """A transit gateway that just reported describe-state "available" can still briefly
    reject dependent operations (e.g. CreateTransitGatewayRouteTable) with IncorrectState
    while the backend finishes propagating that state internally. Poll through that narrow
    window instead of treating it as fatal."""
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


def _table_state(ec2, table_id, treat_notfound_as=None):
    try:
        resp = ec2.describe_transit_gateway_policy_tables(TransitGatewayPolicyTableIds=[table_id])
        tables = resp["TransitGatewayPolicyTables"]
        if not tables:
            return treat_notfound_as
        return tables[0]["State"]
    except ClientError as exc:
        if treat_notfound_as and "NotFound" in exc.response["Error"]["Code"]:
            return treat_notfound_as
        raise


def _route_table_state(ec2, route_table_id, treat_notfound_as=None):
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


def _retry_on_tgw_limit(ec2, fn, timeout_s=1500.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TransitGatewayLimitExceeded" or time.monotonic() >= deadline:
                raise
            _reclaim_stale_tgws(ec2)
            time.sleep(interval_s)


def _reclaim_stale_tgws(ec2, min_age_s=1200.0):
    """Best-effort: free account TGW quota tied up by transit gateways THIS SAME
    self-contained suite created and failed to tear down (e.g. an earlier check in the
    same run that crashed/timed out before its own cleanup ran). Only ever deletes an
    "available" TGW carrying this suite's Name-tag prefix, with no live attachment, AND
    old enough (well beyond any single check's own timeout budget) that it cannot be a
    TGW that a concurrently-running check just created and is still actively wiring up
    (e.g. attaching a route/policy table to, which this reclaim doesn't otherwise see) --
    so it can't yank a resource out from under a check that's mid-flight."""
    try:
        tgws = ec2.describe_transit_gateways(Filters=[{"Name": "state", "Values": ["available"]}])[
            "TransitGateways"
        ]
    except ClientError:
        return
    now = datetime.now(timezone.utc)
    for tgw in tgws:
        name_tag = next((t["Value"] for t in tgw.get("Tags", []) if t["Key"] == "Name"), "")
        if not name_tag.startswith("sim2real-behav-"):
            continue
        creation_time = tgw.get("CreationTime")
        if creation_time is not None and (now - creation_time).total_seconds() < min_age_s:
            continue
        tgw_id = tgw["TransitGatewayId"]
        try:
            live = ec2.describe_transit_gateway_attachments(
                Filters=[
                    {"Name": "transit-gateway-id", "Values": [tgw_id]},
                    {
                        "Name": "state",
                        "Values": [
                            "available", "pending", "pendingAcceptance", "modifying",
                            "initiatingRequest", "rollingBack",
                        ],
                    },
                ]
            )["TransitGatewayAttachments"]
        except ClientError:
            continue
        if live:
            continue
        try:
            ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
        except ClientError:
            pass


def _create_tgw(ctx, ec2, name):
    created = _retry_on_tgw_limit(
        ec2,
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
        timeout_s=180.0,
    )
    return tgw_id



def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidRouteTableID.NotFound",
            "InvalidTransitGatewayID.NotFound",
            "InvalidTransitGatewayPolicyTableId.NotFound",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
