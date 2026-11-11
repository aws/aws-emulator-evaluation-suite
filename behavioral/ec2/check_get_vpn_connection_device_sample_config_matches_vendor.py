"""get-vpn-connection-device-sample-config-matches-vendor."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-vpn-connection-device-sample-config-matches-vendor"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The sample device configuration for a real VPN connection is keyed to that connection's actual tunnel endpoint."""
    ec2 = ctx.client("ec2")
    cgw_id = ec2.create_customer_gateway(
        Type="ipsec.1",
        BgpAsn=65000,
        IpAddress="203.0.113.24",
        TagSpecifications=[_tag_spec("customer-gateway", ctx.unique_name("sim2real-cgw-"))],
    )["CustomerGateway"]["CustomerGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_customer_gateway(CustomerGatewayId=cgw_id))

    vgw_id = ec2.create_vpn_gateway(
        Type="ipsec.1",
        TagSpecifications=[_tag_spec("vpn-gateway", ctx.unique_name("sim2real-vgw-"))],
    )["VpnGateway"]["VpnGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_vpn_gateway(VpnGatewayId=vgw_id))

    # A just-created VPN gateway is not always immediately resolvable by CreateVpnConnection
    # (eventual consistency) -- poll describe_vpn_gateways until it is "available" before
    # referencing it, instead of racing it.
    vgw_state = _wait_vgw_available(ec2, vgw_id)
    assert vgw_state == "available", f"VPN gateway never reached 'available' (state={vgw_state!r})"

    vpn = ec2.create_vpn_connection(
        CustomerGatewayId=cgw_id,
        VpnGatewayId=vgw_id,
        Type="ipsec.1",
        TagSpecifications=[_tag_spec("vpn-connection", ctx.unique_name("sim2real-vpn-"))],
    )["VpnConnection"]
    vpn_id = vpn["VpnConnectionId"]
    ctx.on_cleanup(lambda: ec2.delete_vpn_connection(VpnConnectionId=vpn_id))

    outside_ips = _wait_tunnel_outside_ips(ec2, vpn_id)

    device_types = ec2.get_vpn_connection_device_types()["VpnConnectionDeviceTypes"]
    assert device_types, "no VPN connection device types returned"
    device_type_id = device_types[0]["VpnConnectionDeviceTypeId"]

    config = ec2.get_vpn_connection_device_sample_configuration(
        VpnConnectionId=vpn_id, VpnConnectionDeviceTypeId=device_type_id
    )["VpnConnectionDeviceSampleConfiguration"]

    assert config and len(config) > 100, "sample configuration is unexpectedly empty"
    assert any(ip in config for ip in outside_ips), (
        "sample configuration does not reference this VPN connection's own tunnel outside IP address"
    )


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _wait_vgw_available(ec2, vgw_id, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    state = "unknown"
    while time.monotonic() < deadline:
        gws = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"]
        state = gws[0]["State"] if gws else "unknown"
        if state == "available":
            return state
        time.sleep(interval_s)
    return state


def _wait_tunnel_outside_ips(ec2, vpn_id, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        conn = ec2.describe_vpn_connections(VpnConnectionIds=[vpn_id])["VpnConnections"][0]
        telemetry = conn.get("VgwTelemetry", [])
        ips = [t["OutsideIpAddress"] for t in telemetry if t.get("OutsideIpAddress")]
        if ips:
            return ips
        time.sleep(3)
    raise AssertionError("VPN connection never reported tunnel outside IP addresses")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
