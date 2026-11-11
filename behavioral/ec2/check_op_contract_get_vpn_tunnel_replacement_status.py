"""op-contract-get-vpn-tunnel-replacement-status."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-vpn-tunnel-replacement-status"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetVpnTunnelReplacementStatus: a valid status payload for a real tunnel, NotFound for a bogus connection."""
    ec2 = ctx.client("ec2")

    cgw_id = _create_customer_gateway_with_retry(ec2, ctx)
    ctx.on_cleanup(lambda: ec2.delete_customer_gateway(CustomerGatewayId=cgw_id))

    vgw_id = ec2.create_vpn_gateway(
        Type="ipsec.1",
        TagSpecifications=[_tag_spec("vpn-gateway", ctx.unique_name("sim2real-vgw-"))],
    )["VpnGateway"]["VpnGatewayId"]
    ctx.on_cleanup(lambda: _delete_vpn_gateway(ec2, vgw_id))

    def _vgw_state():
        gateways = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"]
        return gateways[0]["State"] if gateways else None

    _poll_until(_vgw_state, lambda s: s == "available", timeout_s=120, interval_s=3)

    # GetVpnTunnelReplacementStatus requires tunnel lifecycle control to be
    # enabled on the tunnel; without it AWS rejects the call with
    # UnsupportedOperation ("Tunnel lifecycle control is not enabled for
    # tunnel"). Enable it on both tunnels at creation time.
    vpn_id = ec2.create_vpn_connection(
        CustomerGatewayId=cgw_id,
        VpnGatewayId=vgw_id,
        Type="ipsec.1",
        Options={
            "TunnelOptions": [
                {"EnableTunnelLifecycleControl": True},
                {"EnableTunnelLifecycleControl": True},
            ]
        },
        TagSpecifications=[_tag_spec("vpn-connection", ctx.unique_name("sim2real-vpn-"))],
    )["VpnConnection"]["VpnConnectionId"]
    ctx.on_cleanup(lambda: _delete_vpn_connection(ec2, vpn_id))

    described = ec2.describe_vpn_connections(VpnConnectionIds=[vpn_id])["VpnConnections"][0]
    tunnel_options = described["Options"]["TunnelOptions"]
    assert tunnel_options, "expected at least one tunnel option on a newly created VPN connection"
    tunnel_ip = tunnel_options[0]["OutsideIpAddress"]

    # The tunnel's outside IP address is returned immediately by
    # DescribeVpnConnections, but GetVpnTunnelReplacementStatus is backed by a
    # separate (eventually-consistent) system that can take a few seconds to
    # learn about a just-created tunnel; until it does, it rejects the
    # (valid) outside IP with InvalidVpnTunnelOutsideIp.NotFound. Poll for it.
    def _get_status():
        try:
            return ec2.get_vpn_tunnel_replacement_status(
                VpnConnectionId=vpn_id, VpnTunnelOutsideIpAddress=tunnel_ip
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidVpnTunnelOutsideIp.NotFound":
                return None
            raise

    resp = _poll_until(_get_status, lambda r: r is not None, timeout_s=120, interval_s=3)
    assert resp.get("VpnConnectionId") == vpn_id, f"expected VpnConnectionId {vpn_id!r}, got {resp.get('VpnConnectionId')!r}"
    assert resp.get("CustomerGatewayId") == cgw_id, f"expected CustomerGatewayId {cgw_id!r}, got {resp.get('CustomerGatewayId')!r}"
    assert resp.get("VpnGatewayId") == vgw_id, f"expected VpnGatewayId {vgw_id!r}, got {resp.get('VpnGatewayId')!r}"
    assert resp.get("VpnTunnelOutsideIpAddress") == tunnel_ip, (
        f"expected VpnTunnelOutsideIpAddress {tunnel_ip!r}, got {resp.get('VpnTunnelOutsideIpAddress')!r}"
    )
    assert "MaintenanceDetails" in resp, f"expected a MaintenanceDetails block in the response, got keys {sorted(resp)!r}"

    bogus_vpn_id = "vpn-00000000000000000"
    code, message = _error(
        lambda: ec2.get_vpn_tunnel_replacement_status(
            VpnConnectionId=bogus_vpn_id, VpnTunnelOutsideIpAddress=tunnel_ip
        )
    )
    # Unlike most EC2 "invalid resource id" errors (e.g.
    # "InvalidVpnConnectionID.NotFound" used by GetVpnConnectionDeviceSampleConfiguration),
    # GetVpnTunnelReplacementStatus reports an unknown VpnConnectionId with the
    # differently-cased, suffix-less code "InvalidVpnConnectionId" (confirmed
    # against real AWS).
    assert code == "InvalidVpnConnectionId", f"expected InvalidVpnConnectionId, got {code!r}"
    expected = f"The specified VpnConnection ({bogus_vpn_id}) for owner ({ctx.account}) does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last={result!r})")
        time.sleep(interval_s)
        result = probe()
    return result


def _random_test_ip() -> str:
    block = random.choice(["192.0.2", "198.51.100", "203.0.113"])
    return f"{block}.{random.randint(1, 254)}"


def _create_customer_gateway_with_retry(ec2, ctx, attempts: int = 8):
    """Some individual addresses within the RFC 5737 documentation ranges are
    rejected by CreateCustomerGateway as invalid (e.g. reserved sub-blocks like
    192.0.2.224/27). Retry with a freshly generated address on that specific
    error instead of failing on an unlucky pick."""
    last_exc = None
    for _ in range(attempts):
        public_ip = _random_test_ip()
        try:
            return ec2.create_customer_gateway(
                BgpAsn=65000, PublicIp=public_ip, Type="ipsec.1",
                TagSpecifications=[_tag_spec("customer-gateway", ctx.unique_name("sim2real-cgw-"))],
            )["CustomerGateway"]["CustomerGatewayId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValue":
                raise
            last_exc = exc
            continue
    raise last_exc


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises
    AssertionError: a target that accepts what AWS refuses fails loudly here."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _delete_vpn_connection(ec2, vpn_id: str, timeout_s: float = 600.0) -> None:
    """Delete the VPN connection and poll until it reads 'deleted': the VPN gateway and
    customer gateway it uses refuse deletion (IncorrectState) while it is still deleting."""
    ec2.delete_vpn_connection(VpnConnectionId=vpn_id)
    deadline = time.monotonic() + timeout_s
    while True:
        conns = ec2.describe_vpn_connections(VpnConnectionIds=[vpn_id])["VpnConnections"]
        state = conns[0]["State"] if conns else "deleted"
        if state == "deleted":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"VPN connection {vpn_id} did not reach 'deleted' within {timeout_s}s (last {state!r})")
        time.sleep(10)


def _delete_vpn_gateway(ec2, vgw_id: str, timeout_s: float = 300.0) -> None:
    """Delete the VPN gateway, retrying IncorrectState: it reads 'in use' for a while after
    its VPN connection reaches 'deleted'."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_vpn_gateway(VpnGatewayId=vgw_id)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "IncorrectState" or time.monotonic() >= deadline:
                raise
        time.sleep(10)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
