"""delete-transit-gateway-dry-run-does-not-delete-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-transit-gateway-dry-run-does-not-delete-rejected"
GROUP = "overly-permissive"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTransitGateway with DryRun answers DryRunOperation and its exact message and leaves the gateway
    available, while the same call without DryRun takes it to deleted.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgwdry-")

    created = ec2.create_transit_gateway(
        Description=name,
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    tgw_id = created["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id)))

    _poll(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=180.0,
    )

    code, msg = _client_error(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id, DryRun=True))
    assert code == "DryRunOperation", f"unexpected error code for DryRun delete: {code}"
    expected_msg = "Request would have succeeded, but DryRun flag is set."
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # The dry-run must not have actually deleted or started deleting the resource.
    state = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"]
    assert state == "available", f"DryRun delete unexpectedly changed state to {state!r}"

    # Positive control: the identical call, without DryRun, actually deletes it -- so a target
    # that always rejects DeleteTransitGateway (e.g. missing permission) cannot pass by accident.
    delete_resp = ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
    real_state = delete_resp["TransitGateway"]["State"]
    assert real_state in ("deleting", "deleted"), (
        f"real (non-dry-run) delete did not transition state, got {real_state!r}"
    )
    final_state = _poll(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "deleted",
        # Deleting a transit gateway takes several minutes on real AWS.
        timeout_s=900.0,
    )
    assert final_state == "deleted", f"transit gateway never reached deleted state (last={final_state!r})"


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


def _best_effort(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayID.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
