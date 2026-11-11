"""op-contract-deleteTransitGatewayPolicyTable."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteTransitGatewayPolicyTable"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTransitGatewayPolicyTable tears down an available policy table; bogus id -> NotFound."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgwpt-")

    tgw_id = _create_tgw(ctx, ec2, name)

    created = ec2.create_transit_gateway_policy_table(
        TransitGatewayId=tgw_id,
        TagSpecifications=[
            {"ResourceType": "transit-gateway-policy-table", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )
    table_id = created["TransitGatewayPolicyTable"]["TransitGatewayPolicyTableId"]
    ctx.on_cleanup(
        lambda: _best_effort(lambda: ec2.delete_transit_gateway_policy_table(TransitGatewayPolicyTableId=table_id))
    )

    state = _poll(
        lambda: _table_state(ec2, table_id),
        lambda s: s == "available",
        timeout_s=120.0,
    )
    assert state == "available", f"policy table never became available (last={state})"

    delete_resp = ec2.delete_transit_gateway_policy_table(TransitGatewayPolicyTableId=table_id)
    delete_state = delete_resp["TransitGatewayPolicyTable"]["State"]
    assert delete_state in ("deleting", "deleted"), f"unexpected state after delete: {delete_state}"

    final_state = _poll(
        lambda: _table_state(ec2, table_id, treat_notfound_as="deleted"),
        lambda s: s == "deleted",
        timeout_s=120.0,
    )
    assert final_state == "deleted", f"policy table never reached deleted (last={final_state})"

    bogus_table_id = _bogus_id_like(table_id)
    error = _error(
        lambda: ec2.delete_transit_gateway_policy_table(TransitGatewayPolicyTableId=bogus_table_id)
    )
    assert error["Code"] == "InvalidTransitGatewayPolicyTableId.NotFound", error
    assert error.get("Message") == f"Transit Gateway Policy Table {bogus_table_id} was deleted or does not exist.", error


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
        timeout_s=180.0,
    )
    return tgw_id


def _retry_on_tgw_limit(fn, timeout_s=600.0, interval_s=20.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TransitGatewayLimitExceeded" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidTransitGatewayID.NotFound",
            "InvalidTransitGatewayPolicyTableId.NotFound",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
