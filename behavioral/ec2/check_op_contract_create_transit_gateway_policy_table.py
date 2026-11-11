"""op-contract-create-transit-gateway-policy-table."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-transit-gateway-policy-table"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTransitGatewayPolicyTable: success creates a policy table bound to the
    transit gateway; DryRun=True is honored (permission-checked, no mutation)."""
    ec2 = ctx.client("ec2")
    tgw_id = _create_tgw(ctx)
    _wait_tgw_available(ctx, tgw_id)

    before = len(
        ec2.describe_transit_gateway_policy_tables(
            Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}]
        )["TransitGatewayPolicyTables"]
    )

    # --- error boundary: DryRun must fail with DryRunOperation and create nothing ---
    code, message = _error(
        lambda: ec2.create_transit_gateway_policy_table(TransitGatewayId=tgw_id, DryRun=True)
    )
    assert code == "DryRunOperation", f"unexpected code: {code}"
    assert message == _DRY_RUN_MESSAGE, f"unexpected DryRunOperation message {message!r}"
    after_dry_run = len(
        ec2.describe_transit_gateway_policy_tables(
            Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}]
        )["TransitGatewayPolicyTables"]
    )
    assert after_dry_run == before, "DryRun must not create a policy table"

    # --- success path ---
    table_name = ctx.unique_name("sim2real-behav-tgwpt-")
    resp = ec2.create_transit_gateway_policy_table(
        TransitGatewayId=tgw_id,
        TagSpecifications=[
            {"ResourceType": "transit-gateway-policy-table", "Tags": [{"Key": "Name", "Value": table_name}]}
        ],
    )
    table = resp["TransitGatewayPolicyTable"]
    table_id = table["TransitGatewayPolicyTableId"]
    ctx.on_cleanup(lambda: _delete_policy_table(ctx, table_id))
    assert table["TransitGatewayId"] == tgw_id, f"table bound to {table['TransitGatewayId']!r}, expected {tgw_id!r}"
    assert table["State"] in ("pending", "available"), table["State"]

    final_state = _poll_until(
        lambda: ec2.describe_transit_gateway_policy_tables(TransitGatewayPolicyTableIds=[table_id])[
            "TransitGatewayPolicyTables"
        ][0]["State"],
        lambda s: s in ("available", "failed"),
        timeout_s=90.0,
    )
    assert final_state == "available", f"policy table ended in {final_state}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that succeeds
    raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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


def _delete_policy_table(ctx, table_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_transit_gateway_policy_table(TransitGatewayPolicyTableId=table_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayPolicyTableId.NotFound":
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
