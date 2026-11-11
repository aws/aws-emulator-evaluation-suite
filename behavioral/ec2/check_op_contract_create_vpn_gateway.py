"""op-contract-createVpnGateway."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-createVpnGateway"
GROUP = "error-semantics"
SERVICES = ["ec2"]

_DRY_RUN_MESSAGE = "Request would have succeeded, but DryRun flag is set."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpnGateway: success creates a standalone virtual private gateway with the requested
    Amazon-side ASN; DryRun short-circuits before creation."""
    ec2 = ctx.client("ec2")

    # Error boundary: DryRun must short-circuit before creating anything.
    err = _client_error(lambda: ec2.create_vpn_gateway(Type="ipsec.1", DryRun=True))
    assert err.get("Code") == "DryRunOperation", f"expected DryRunOperation, got {err!r}"
    assert err.get("Message") == _DRY_RUN_MESSAGE, f"unexpected DryRun message: {err!r}"

    name = ctx.unique_name("sim2real-cvgw-")
    resp = ec2.create_vpn_gateway(
        Type="ipsec.1",
        AmazonSideAsn=65010,
        TagSpecifications=[{"ResourceType": "vpn-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    gateway_id = resp["VpnGateway"]["VpnGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_vpn_gateway(VpnGatewayId=gateway_id))

    # Independent terminal read: the create call's own response is never the verdict.
    described = _poll_until(
        lambda: ec2.describe_vpn_gateways(VpnGatewayIds=[gateway_id])["VpnGateways"][0],
        lambda g: g["State"] == "available",
        timeout_s=60.0,
    )
    assert described["State"] == "available", f"expected available, got {described['State']!r}"
    assert described["Type"] == "ipsec.1", f"expected ipsec.1, got {described['Type']!r}"
    assert described["AmazonSideAsn"] == 65010, f"expected 65010, got {described['AmazonSideAsn']!r}"
    assert described.get("VpcAttachments", []) == [], f"expected no attachments, got {described.get('VpcAttachments')!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
