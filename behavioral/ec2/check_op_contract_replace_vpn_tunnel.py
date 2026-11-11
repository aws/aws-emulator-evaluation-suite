"""op-contract-replace-vpn-tunnel."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-replace-vpn-tunnel"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ReplaceVpnTunnel rejects a malformed (not a valid IPv4 address) value
    as the tunnel's outside IP without touching the connection, and then
    triggers replacement of a real tunnel endpoint (success contract)."""
    ec2 = ctx.client("ec2")

    cgw_id = ec2.create_customer_gateway(
        BgpAsn=65000, PublicIp="203.0.113.12", Type="ipsec.1",
        TagSpecifications=_tags("customer-gateway", ctx.unique_name("sim2real-rvt-")),
    )["CustomerGateway"]["CustomerGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_customer_gateway(CustomerGatewayId=cgw_id))
    _poll_until(lambda: ec2.describe_customer_gateways(CustomerGatewayIds=[cgw_id])["CustomerGateways"][0]["State"],
                lambda s: s == "available", timeout_s=60, interval_s=2)

    # The VPN-gateway quota is low, so a create that hits
    # VpnGatewayLimitExceeded is retried until a slot frees up.
    vgw_id = _poll_until_success(
        lambda: ec2.create_vpn_gateway(
            Type="ipsec.1", TagSpecifications=_tags("vpn-gateway", ctx.unique_name("sim2real-rvt-")),
        )["VpnGateway"]["VpnGatewayId"],
        retryable_codes={"VpnGatewayLimitExceeded"}, timeout_s=240, interval_s=15)
    # DeleteVpnGateway keeps reporting IncorrectState for a while after the
    # attached VPN connection reads "deleted", so the delete is retried.
    ctx.on_cleanup(lambda: _poll_until_success(
        lambda: ec2.delete_vpn_gateway(VpnGatewayId=vgw_id),
        retryable_codes={"IncorrectState"}, timeout_s=600, interval_s=15))
    _poll_until(lambda: ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"][0]["State"],
                lambda s: s == "available", timeout_s=60, interval_s=2)

    conn = ec2.create_vpn_connection(
        CustomerGatewayId=cgw_id, VpnGatewayId=vgw_id, Type="ipsec.1",
        TagSpecifications=_tags("vpn-connection", ctx.unique_name("sim2real-rvt-")),
    )["VpnConnection"]
    conn_id = conn["VpnConnectionId"]

    def _delete_connection():
        ec2.delete_vpn_connection(VpnConnectionId=conn_id)
        _poll_until(lambda: ec2.describe_vpn_connections(VpnConnectionIds=[conn_id])["VpnConnections"][0]["State"],
                    lambda s: s == "deleted", timeout_s=900, interval_s=15)

    ctx.on_cleanup(_delete_connection)
    conn = _poll_until(
        lambda: ec2.describe_vpn_connections(VpnConnectionIds=[conn_id])["VpnConnections"][0],
        lambda c: c["State"] == "available", timeout_s=600, interval_s=15)

    tunnel_options = conn["Options"]["TunnelOptions"]
    if not tunnel_options:
        raise AssertionError("VPN connection has no tunnel options to replace")
    outside_ip = tunnel_options[0]["OutsideIpAddress"]
    before_ips = {o["OutsideIpAddress"] for o in tunnel_options}

    # The malformed address is sent while the connection is "available": a
    # replacement in flight puts the connection in "modifying", and AWS then
    # refuses every ReplaceVpnTunnel with a state conflict before it looks at
    # the address.
    malformed_ip = "999.999.999.999"
    code, message = _expect_error(
        lambda: ec2.replace_vpn_tunnel(VpnConnectionId=conn_id, VpnTunnelOutsideIpAddress=malformed_ip))
    assert code == "InvalidVpnTunnelOutsideIp.NotFound", (
        f"expected InvalidVpnTunnelOutsideIp.NotFound, got {code}")
    expected_message = f"Outside IP Address {malformed_ip} not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # The rejected call must have had zero effect. Prove it through a different
    # operation than the one we just asserted on: an independent DescribeVpnConnections
    # read must still show the connection's original, untouched tunnel endpoints.
    after = ec2.describe_vpn_connections(VpnConnectionIds=[conn_id])["VpnConnections"][0]
    after_ips = {o["OutsideIpAddress"] for o in after["Options"]["TunnelOptions"]}
    assert after_ips == before_ips, (
        f"the rejected ReplaceVpnTunnel call (malformed outside IP) altered the connection's "
        f"tunnel endpoints: expected {before_ips!r}, got {after_ips!r}"
    )
    assert after["State"] == "available", (
        f"the rejected ReplaceVpnTunnel call moved the connection out of available: {after['State']!r}")

    resp = ec2.replace_vpn_tunnel(VpnConnectionId=conn_id, VpnTunnelOutsideIpAddress=outside_ip)
    assert resp["Return"] is True, f"ReplaceVpnTunnel(valid outside IP) did not report success: {resp}"


def _tags(resource_type: str, name: str) -> list[dict]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _poll_until_success(fn, retryable_codes, timeout_s=120.0, interval_s=5.0):
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in retryable_codes:
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _expect_error(fn):
    """Call fn() once and return the refusal's (code, message). A call that
    succeeds is an AssertionError: the caller expects a refusal."""
    from botocore.exceptions import ClientError
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {resp!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
