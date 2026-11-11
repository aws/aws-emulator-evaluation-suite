"""op-contract-attachVpnGateway."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-attachVpnGateway"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AttachVpnGateway attaches a virtual private gateway to a VPC; a nonexistent gateway is rejected."""
    ec2 = ctx.client("ec2")

    vpc = _create_vpc_retrying(ec2, "10.205.0.0/16")
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc))

    vgw = ec2.create_vpn_gateway(
        Type="ipsec.1",
        TagSpecifications=[{"ResourceType": "vpn-gateway", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["VpnGateway"]["VpnGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_vpn_gateway(VpnGatewayId=vgw))
    _poll_until(
        lambda: ec2.describe_vpn_gateways(VpnGatewayIds=[vgw])["VpnGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=60,
        interval_s=2,
    )

    # error boundary: gateway does not exist. Use a well-formed-but-nonexistent ID (mixed hex
    # digits, not all zeros) -- an all-zero suffix can trip AWS's ID-format check first and come
    # back as "...Malformed" instead of "...NotFound".
    code, code_message = _error_code(lambda: ec2.attach_vpn_gateway(VpnGatewayId="vgw-0123456789abcdef0", VpcId=vpc))
    assert code == "InvalidVpnGatewayID.NotFound", f"expected InvalidVpnGatewayID.NotFound, got {code}"
    expected_code_message = "The vpnGateway ID 'vgw-0123456789abcdef0' does not exist"
    assert code_message == expected_code_message, f"expected message {expected_code_message!r}, got {code_message!r}"

    # success path
    resp = ec2.attach_vpn_gateway(VpnGatewayId=vgw, VpcId=vpc)
    assert resp["VpcAttachment"]["VpcId"] == vpc, f"expected attachment on {vpc}, got {resp['VpcAttachment']!r}"
    assert resp["VpcAttachment"]["State"] in ("attaching", "attached"), (
        f"expected attaching/attached, got {resp['VpcAttachment']['State']!r}"
    )

    def cleanup_attach():
        try:
            ec2.detach_vpn_gateway(VpnGatewayId=vgw, VpcId=vpc)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVpnGatewayID.NotFound":
                raise

    ctx.on_cleanup(cleanup_attach)

    final = _poll_until(
        lambda: ec2.describe_vpn_gateways(VpnGatewayIds=[vgw])["VpnGateways"][0]["VpcAttachments"],
        lambda atts: bool(atts) and atts[0]["State"] == "attached",
        timeout_s=60,
        interval_s=2,
    )
    assert final[0]["VpcId"] == vpc, f"expected final attachment on {vpc}, got {final[0]!r}"
    assert final[0]["State"] == "attached", f"expected attached, got {final[0]['State']!r}"

    # Detach synchronously in the body (not just in cleanup): detachment is asynchronous and
    # commonly lingers past 30s on real AWS, well beyond the harness's 60s cleanup budget --
    # doing it here, with a generous bounded wait, is what lets delete_vpn_gateway/delete_vpc
    # in cleanup actually succeed instead of racing a still-attached VPC.
    ec2.detach_vpn_gateway(VpnGatewayId=vgw, VpcId=vpc)
    detached = _poll_until(
        lambda: [
            att
            for att in ec2.describe_vpn_gateways(VpnGatewayIds=[vgw])["VpnGateways"][0]["VpcAttachments"]
            if att["VpcId"] == vpc
        ],
        lambda atts: bool(atts) and atts[0]["State"] == "detached",
        timeout_s=300,
        interval_s=5,
    )
    assert detached[0]["State"] == "detached", f"expected detached, got {detached[0]!r}"


def _create_vpc_retrying(ec2, cidr: str, *, timeout_s: float = 300.0, interval_s: float = 10.0) -> str:
    """create_vpc can transiently fail with VpcLimitExceeded when sibling checks running
    concurrently in the same account/region are holding their own scratch VPCs; retry with
    backoff so this check succeeds once they finish and their own cleanup releases quota,
    instead of treating a shared-account capacity blip as a hard failure."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpc(
                CidrBlock=cidr,
                TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
            )["Vpc"]["VpcId"]
        except Exception as exc:
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            if code != "VpcLimitExceeded" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except Exception as exc:
        err = getattr(exc, "response", {}).get("Error")
        if not err:
            raise
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
