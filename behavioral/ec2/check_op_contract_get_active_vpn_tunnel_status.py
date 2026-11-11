"""op-contract-get-active-vpn-tunnel-status."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "op-contract-get-active-vpn-tunnel-status"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetActiveVpnTunnelStatus reports ProvisioningStatus "available" for a provisioned tunnel's
    outside IP (endpoint provisioning, not an IKE session); an unknown VpnConnectionId fails with
    InvalidVpnConnectionID.NotFound and its exact message."""
    ec2 = ctx.client("ec2")

    cgw_id = ec2.create_customer_gateway(
        BgpAsn=65000, PublicIp="203.0.113.12", Type="ipsec.1",
        TagSpecifications=[_tag_spec(ctx, "customer-gateway", "cgw")],
    )["CustomerGateway"]["CustomerGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_customer_gateway(CustomerGatewayId=cgw_id))
    _wait_for(lambda: _cgw_available(ec2, cgw_id), timeout_s=60)

    vgw_id = ec2.create_vpn_gateway(
        Type="ipsec.1", TagSpecifications=[_tag_spec(ctx, "vpn-gateway", "vgw")]
    )["VpnGateway"]["VpnGatewayId"]
    ctx.on_cleanup(lambda: _delete_vpn_gateway(ec2, vgw_id))
    # CreateVpnConnection requires the VGW to have fully propagated -- immediately after
    # CreateVpnGateway returns, the ID can still be unresolvable (InvalidVpnGatewayID.NotFound).
    _wait_for(lambda: _vgw_available(ec2, vgw_id), timeout_s=60)

    conn = ec2.create_vpn_connection(
        CustomerGatewayId=cgw_id,
        VpnGatewayId=vgw_id,
        Type="ipsec.1",
        Options={"StaticRoutesOnly": True},
        TagSpecifications=[_tag_spec(ctx, "vpn-connection", "vpn")],
    )["VpnConnection"]
    conn_id = conn["VpnConnectionId"]
    ctx.on_cleanup(lambda: _delete_vpn_connection(ec2, conn_id))

    # CreateVpnConnection's immediate response -- and even the first few
    # DescribeVpnConnections calls -- can have an empty VgwTelemetry list while AWS
    # finishes provisioning the tunnel endpoints; poll until telemetry appears.
    outside_ip = _wait_for_telemetry(ec2, conn_id)

    # --- success path: the tunnel endpoint is provisioned and reports "available" even
    # though this tunnel's peer (203.0.113.12) never negotiates IPSec. Pinning the one value AWS
    # reports, not any of the three modelled ProvisioningStatus values, makes this a real assertion.
    resp = _wait_for_active_tunnel_status(ec2, conn_id, outside_ip)
    status = resp["ActiveVpnTunnelStatus"]
    assert status["ProvisioningStatus"] == "available", status

    # --- error boundary: nonexistent VPN connection id ---
    code, message = _error(lambda: ec2.get_active_vpn_tunnel_status(
        VpnConnectionId="vpn-00000000000000000", VpnTunnelOutsideIpAddress=outside_ip
    ))
    assert code == "InvalidVpnConnectionID.NotFound", code
    assert message == "The vpn-connection ID 'vpn-00000000000000000' does not exist", message


def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _cgw_available(ec2: Any, cgw_id: str) -> bool:
    cgw = ec2.describe_customer_gateways(CustomerGatewayIds=[cgw_id])["CustomerGateways"][0]
    return cgw["State"] == "available"


def _wait_for_telemetry(ec2: Any, conn_id: str, timeout_s: float = 60.0, interval_s: float = 3.0) -> str:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        conn = ec2.describe_vpn_connections(VpnConnectionIds=[conn_id])["VpnConnections"][0]
        telemetry = conn.get("VgwTelemetry") or []
        if telemetry:
            return telemetry[0]["OutsideIpAddress"]
        time.sleep(interval_s)
    raise AssertionError("VgwTelemetry never appeared on the VPN connection")


def _wait_for_active_tunnel_status(ec2: Any, conn_id: str, outside_ip: str,
                                    timeout_s: float = 120.0, interval_s: float = 5.0) -> dict:
    """Even after VgwTelemetry lists a tunnel's outside IP, GetActiveVpnTunnelStatus's
    separate backing store can lag behind and reject that same, genuine outside IP
    with InvalidParameter ("does not correspond to ...") for a short additional
    window while the tunnel finishes provisioning; poll until it's recognized."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return ec2.get_active_vpn_tunnel_status(
                VpnConnectionId=conn_id, VpnTunnelOutsideIpAddress=outside_ip
            )
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] != "InvalidParameter":
                raise
            time.sleep(interval_s)
    raise last_exc  # type: ignore[misc]


def _vgw_available(ec2: Any, vgw_id: str) -> bool:
    try:
        vgw = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"][0]
    except Exception:
        return False
    return vgw["State"] == "available"


def _delete_vpn_connection(ec2: Any, conn_id: str) -> None:
    ec2.delete_vpn_connection(VpnConnectionId=conn_id)
    _wait_for(lambda: _connection_deleted(ec2, conn_id), timeout_s=120)



def _delete_vpn_gateway(ec2: Any, vgw_id: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> None:
    """Delete the VPN gateway, retrying while a just-deleted VPN connection still holds it
    (DeleteVpnGateway answers IncorrectState until the gateway is released)."""
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_vpn_gateway(VpnGatewayId=vgw_id)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "IncorrectState" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)

def _connection_deleted(ec2: Any, conn_id: str) -> bool:
    conn = ec2.describe_vpn_connections(VpnConnectionIds=[conn_id])["VpnConnections"][0]
    return conn["State"] == "deleted"


def _wait_for(predicate: Callable[[], bool], timeout_s: float = 60.0, interval_s: float = 3.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(interval_s)
    raise AssertionError("condition not met within timeout")


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn() and return the (code, message) of the ClientError it raises. A call
    that succeeds raises AssertionError, because an emulator accepting what real AWS
    refuses must not read as a mere code mismatch."""
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
