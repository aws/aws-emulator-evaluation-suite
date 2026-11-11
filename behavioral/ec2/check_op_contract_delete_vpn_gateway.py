"""op-contract-delete-vpn-gateway."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-delete-vpn-gateway"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteVpnGateway: success transitions the gateway to deleted; deleting an unknown/already-deleted id 404s."""
    ec2 = ctx.client("ec2")

    created = ec2.create_vpn_gateway(
        Type="ipsec.1",
        TagSpecifications=[
            {
                "ResourceType": "vpn-gateway",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-vgw-")}],
            }
        ],
    )
    vgw_id = created["VpnGateway"]["VpnGatewayId"]
    assert created["VpnGateway"]["State"] in ("pending", "available"), (
        f"expected pending/available on create, got {created['VpnGateway']['State']}"
    )

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            ec2.delete_vpn_gateway(VpnGatewayId=vgw_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVpnGatewayID.NotFound":
                raise

    ctx.on_cleanup(_cleanup)

    # wait for the gateway to reach 'available' before deleting it
    def _describe_state():
        resp = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])
        return resp["VpnGateways"][0]["State"]

    state = _poll_until(_describe_state, lambda s: s == "available", timeout_s=60, interval_s=2)
    assert state == "available", f"vpn gateway never became available, last state={state}"

    # success path: delete and confirm the state transition to deleted
    ec2.delete_vpn_gateway(VpnGatewayId=vgw_id)
    final_state = _poll_until(_describe_state, lambda s: s == "deleted", timeout_s=60, interval_s=2)
    assert final_state == "deleted", f"vpn gateway never reached deleted state, last={final_state}"

    # error boundary: deleting an already-deleted (thus now-unknown) gateway id 404s
    error = _error(lambda: ec2.delete_vpn_gateway(VpnGatewayId=vgw_id))
    assert error["Code"] == "InvalidVpnGatewayID.NotFound", error
    assert error.get("Message") == f"The vpnGateway ID '{vgw_id}' does not exist", error

    # error boundary #2: a syntactically valid but never-issued id also 404s
    never_issued_id = "vgw-00000000000000000"
    error2 = _error(lambda: ec2.delete_vpn_gateway(VpnGatewayId=never_issued_id))
    assert error2["Code"] == "InvalidVpnGatewayID.NotFound", error2
    assert error2.get("Message") == f"The vpnGateway ID '{never_issued_id}' does not exist", error2


def _error(fn):
    """Call fn() and return its botocore Error dict; a call that succeeds raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise TimeoutError(f"timed out after {timeout_s}s waiting for predicate, last observed={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
