"""op-contract-describe-vpn-gateways."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-describe-vpn-gateways"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeVpnGateways: success returns the created VPN gateway with the correct Type
    once it settles into 'available'; a bogus VpnGatewayId is rejected with the specific
    InvalidVpnGatewayID.NotFound error."""
    ec2 = ctx.client("ec2")

    vgw_id = ec2.create_vpn_gateway(
        Type="ipsec.1",
        TagSpecifications=_tag_spec(ctx, "vpn-gateway", ctx.unique_name("sim2real-dvgw-")),
    )["VpnGateway"]["VpnGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_vpn_gateway(VpnGatewayId=vgw_id))

    described = _poll_until(
        lambda: ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"][0],
        lambda g: g["State"] == "available",
        timeout_s=30.0,
    )
    assert described["Type"] == "ipsec.1", f"expected Type ipsec.1, got {described['Type']!r}"
    assert described["VpnGatewayId"] == vgw_id, f"expected VpnGatewayId {vgw_id}, got {described['VpnGatewayId']!r}"

    code, message = _client_error(lambda: ec2.describe_vpn_gateways(VpnGatewayIds=["vgw-00000000000000000"]))
    assert code == "InvalidVpnGatewayID.NotFound", f"expected InvalidVpnGatewayID.NotFound, got {code!r}"
    expected_message = "The vpnGateway ID 'vgw-00000000000000000' does not exist"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _tag_spec(ctx, resource_type: str, name: str):
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because a target
    that accepts input real AWS rejects is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
