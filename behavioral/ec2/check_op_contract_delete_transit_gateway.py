"""op-contract-deleteTransitGateway."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteTransitGateway"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTransitGateway transitions an available TGW to deleted, is idempotent once deleted,
    and bogus id -> NotFound."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgw-")

    created = ec2.create_transit_gateway(
        Description=name,
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    tgw_id = created["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _best_effort_delete_tgw(ec2, tgw_id))

    state = _poll(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=180.0,
    )
    assert state == "available", f"transit gateway never became available (last={state})"

    delete_resp = ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
    assert delete_resp["TransitGateway"]["State"] in ("deleting", "deleted"), delete_resp["TransitGateway"]["State"]

    final_state = _poll(
        lambda: _describe_tgw_state_or_deleted(ec2, tgw_id),
        lambda s: s == "deleted",
        timeout_s=600.0,
    )
    assert final_state == "deleted", f"transit gateway never reached deleted (last={final_state})"

    # A second delete of the same already-deleted id is idempotent on real EC2: it succeeds again
    # (no NotFound) as long as the id is still visible in State=deleted, echoing that same state.
    redelete_resp = ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
    assert redelete_resp["TransitGateway"]["State"] == "deleted", redelete_resp["TransitGateway"]["State"]

    bogus_id = "tgw-0123456789abcdef0"
    code, msg = _client_error(lambda: ec2.delete_transit_gateway(TransitGatewayId=bogus_id))
    assert code == "InvalidTransitGatewayID.NotFound", f"unexpected error code: {code}"
    expected_msg = f"Transit Gateway {bogus_id} was deleted or does not exist."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _poll(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _client_error(fn):
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _describe_tgw_state_or_deleted(ec2, tgw_id):
    try:
        return ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"]
    except ClientError as exc:
        if "NotFound" in exc.response["Error"]["Code"]:
            return "deleted"
        raise


def _best_effort_delete_tgw(ec2, tgw_id):
    try:
        ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayID.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
