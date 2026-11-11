"""e2e-vpn-tunnel-cert-rotation-flow."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-vpn-tunnel-cert-rotation-flow"
GROUP = "e2e"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVpnTunnelCertificate on a PSK tunnel fails UnsupportedOperation with its exact message
    and leaves CertificateArn unchanged; ModifyVpnTunnelOptions sets DPD timeout 45, the device
    sample config names the tunnel IP, and ModifyVpnConnection moves it to a second gateway.
    """
    ec2 = ctx.client("ec2")

    cgw_id = ec2.create_customer_gateway(
        BgpAsn=65000,
        PublicIp="203.0.113.11",
        Type="ipsec.1",
        TagSpecifications=_tag_spec(ctx, "customer-gateway", "cgw"),
    )["CustomerGateway"]["CustomerGatewayId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_customer_gateway(CustomerGatewayId=cgw_id)))
    _poll_until(
        lambda: ec2.describe_customer_gateways(CustomerGatewayIds=[cgw_id])[
            "CustomerGateways"
        ][0]["State"],
        lambda state: state == "available",
        timeout_s=120,
    )

    vgw1_id = _create_vpn_gateway_with_retry(
        ec2, Type="ipsec.1", TagSpecifications=_tag_spec(ctx, "vpn-gateway", "vgw1")
    )
    ctx.on_cleanup(lambda: _delete_vpn_gateway_with_retry(ec2, vgw1_id))
    vgw2_id = _create_vpn_gateway_with_retry(
        ec2, Type="ipsec.1", TagSpecifications=_tag_spec(ctx, "vpn-gateway", "vgw2")
    )
    ctx.on_cleanup(lambda: _delete_vpn_gateway_with_retry(ec2, vgw2_id))
    for vgw_id in (vgw1_id, vgw2_id):
        _poll_until(
            lambda vid=vgw_id: ec2.describe_vpn_gateways(VpnGatewayIds=[vid])["VpnGateways"][0][
                "State"
            ],
            lambda state: state == "available",
            timeout_s=120,
        )

    conn = ec2.create_vpn_connection(
        CustomerGatewayId=cgw_id,
        VpnGatewayId=vgw1_id,
        Type="ipsec.1",
        Options={"StaticRoutesOnly": True},
        TagSpecifications=_tag_spec(ctx, "vpn-connection", "vpn"),
    )["VpnConnection"]
    conn_id = conn["VpnConnectionId"]
    ctx.on_cleanup(lambda: _delete_vpn_connection_and_wait(ec2, conn_id))

    # A Site-to-Site VPN connection can take well over 5 minutes to reach "available" with
    # tunnel telemetry present.
    conn = _poll_until(
        lambda: ec2.describe_vpn_connections(VpnConnectionIds=[conn_id])["VpnConnections"][0],
        lambda c: c["State"] == "available" and len(c.get("VgwTelemetry", [])) >= 1,
        timeout_s=900,
        interval_s=10.0,
    )
    tunnel_ip = conn["VgwTelemetry"][0]["OutsideIpAddress"]
    old_cert_arn = conn["VgwTelemetry"][0].get("CertificateArn")

    # --- Rotating the tunnel endpoint certificate is rejected: this tunnel was
    # never provisioned for certificate-based authentication. ---
    from botocore.exceptions import ClientError

    try:
        ec2.modify_vpn_tunnel_certificate(
            VpnConnectionId=conn_id, VpnTunnelOutsideIpAddress=tunnel_ip
        )
        raise AssertionError(
            "ModifyVpnTunnelCertificate unexpectedly succeeded on a PSK-based tunnel"
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message", "")
        assert code == "UnsupportedOperation", (
            f"expected UnsupportedOperation rotating a cert on a PSK-based tunnel, got {code}: {message}"
        )
        assert message == f"The VPN Connection {conn_id} is not a Certificate Based VPN.", (
            f"expected the specific 'not a Certificate Based VPN' refusal, got: {message!r}"
        )

    def _tunnel_telemetry():
        c = ec2.describe_vpn_connections(VpnConnectionIds=[conn_id])["VpnConnections"][0]
        return next(
            (t for t in c["VgwTelemetry"] if t["OutsideIpAddress"] == tunnel_ip), None
        )

    unrotated = _tunnel_telemetry()
    assert unrotated is not None, f"tunnel {tunnel_ip} vanished from VgwTelemetry"
    assert unrotated.get("CertificateArn") == old_cert_arn, (
        f"expected CertificateArn unchanged by the rejected call, was {old_cert_arn!r} "
        f"now {unrotated.get('CertificateArn')!r}"
    )

    # --- Change tunnel options: reflected on the next describe. SkipTunnelReplacement applies
    # only to EnableTunnelLifecycleControl (UnsupportedOperation otherwise), so the DPD timeout /
    # PSK change goes through an ordinary, replacing tunnel modification. ---
    ec2.modify_vpn_tunnel_options(
        VpnConnectionId=conn_id,
        VpnTunnelOutsideIpAddress=tunnel_ip,
        TunnelOptions={"DPDTimeoutSeconds": 45, "PreSharedKey": "Sim2RealTunnelPSK2024x"},
    )

    def _tunnel_option():
        c = ec2.describe_vpn_connections(VpnConnectionIds=[conn_id])["VpnConnections"][0]
        opts = c["Options"].get("TunnelOptions", [])
        return next((o for o in opts if o["OutsideIpAddress"] == tunnel_ip), None)

    updated_opt = _poll_until(
        _tunnel_option, lambda o: o is not None and o.get("DpdTimeoutSeconds") == 45, timeout_s=300
    )
    assert updated_opt["DpdTimeoutSeconds"] == 45, (
        f"expected DPDTimeoutSeconds=45 on the next describe, got {updated_opt}"
    )

    # --- The PSK change replaces the tunnel session: until the connection is "available" again,
    # ModifyVpnConnection fails InvalidVpnConnection.InvalidState, so wait for that first. ---
    settled = _poll_until(
        lambda: ec2.describe_vpn_connections(VpnConnectionIds=[conn_id])["VpnConnections"][0],
        lambda c: c["State"] == "available",
        timeout_s=900,
        interval_s=10.0,
    )
    assert settled["State"] == "available", (
        f"expected the connection back to available after the tunnel option change, "
        f"got {settled.get('State')!r}"
    )

    # --- The device sample configuration names this exact tunnel endpoint. ---
    device_types = ec2.get_vpn_connection_device_types()["VpnConnectionDeviceTypes"]
    assert device_types, "GetVpnConnectionDeviceTypes returned no device types"
    device_type_id = device_types[0]["VpnConnectionDeviceTypeId"]
    sample = ec2.get_vpn_connection_device_sample_configuration(
        VpnConnectionId=conn_id, VpnConnectionDeviceTypeId=device_type_id
    )["VpnConnectionDeviceSampleConfiguration"]
    assert tunnel_ip in sample, (
        f"expected tunnel outside IP {tunnel_ip} in the generated device sample config"
    )

    # --- Migrate the connection to a different virtual private gateway. ---
    ec2.modify_vpn_connection(VpnConnectionId=conn_id, VpnGatewayId=vgw2_id)
    migrated = _poll_until(
        lambda: ec2.describe_vpn_connections(VpnConnectionIds=[conn_id])["VpnConnections"][0],
        lambda c: c.get("VpnGatewayId") == vgw2_id,
        timeout_s=180,
    )
    assert migrated["VpnGatewayId"] == vgw2_id, (
        f"expected connection migrated to {vgw2_id}, describe shows {migrated.get('VpnGatewayId')!r}"
    )


def _create_vpn_gateway_with_retry(ec2, timeout_s=600.0, interval_s=15.0, **kwargs):
    # The virtual private gateway quota (default 5 per region) can be exhausted for a while by
    # gateways still being deleted, so VpnGatewayLimitExceeded is retried to a bounded deadline.
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ec2.create_vpn_gateway(**kwargs)["VpnGateway"]["VpnGatewayId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "VpnGatewayLimitExceeded" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _delete_vpn_connection_and_wait(ec2, conn_id, timeout_s=600.0):
    """Delete the connection and wait for deleted: its gateways refuse deletion until then."""
    ec2.delete_vpn_connection(VpnConnectionId=conn_id)
    _poll_until(
        lambda: ec2.describe_vpn_connections(VpnConnectionIds=[conn_id])["VpnConnections"],
        lambda rows: not rows or rows[0]["State"] == "deleted",
        timeout_s=timeout_s,
        interval_s=10.0,
    )


def _delete_vpn_gateway_with_retry(ec2, vgw_id, timeout_s=300.0, interval_s=10.0):
    """A gateway whose connection just reached deleted can still refuse as in use for a short
    settling window; retry through it rather than leak the gateway."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_vpn_gateway(VpnGatewayId=vgw_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("DependencyViolation", "IncorrectState") and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _tag_spec(ctx, resource_type, prefix):
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
        }
    ]


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidCustomerGatewayID.NotFound":
            raise


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
