"""op-contract-deleteVpnConnection."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteVpnConnection"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteVpnConnection tears down a VPN connection; a bogus connection id is rejected NotFound."""
    ec2 = ctx.client("ec2")

    cgw_id = ec2.create_customer_gateway(
        BgpAsn=65000,
        PublicIp="203.0.113.55",
        Type="ipsec.1",
        TagSpecifications=[_tag_spec(ctx, "customer-gateway", "cgw")],
    )["CustomerGateway"]["CustomerGatewayId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_customer_gateway(CustomerGatewayId=cgw_id)))

    vgw_id = ec2.create_vpn_gateway(
        Type="ipsec.1", TagSpecifications=[_tag_spec(ctx, "vpn-gateway", "vgw")]
    )["VpnGateway"]["VpnGatewayId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_vpn_gateway(VpnGatewayId=vgw_id)))

    # the gateway must be describable/available before it can be referenced by CreateVpnConnection
    _poll_until(
        lambda: _vgw_state(ec2, vgw_id),
        lambda s: s == "available",
        timeout_s=60.0,
    )

    created = ec2.create_vpn_connection(
        Type="ipsec.1",
        CustomerGatewayId=cgw_id,
        VpnGatewayId=vgw_id,
        Options={"StaticRoutesOnly": True},
        TagSpecifications=[_tag_spec(ctx, "vpn-connection", "vpn")],
    )
    vpn_id = created["VpnConnection"]["VpnConnectionId"]
    state = {"deleted": False}

    def _cleanup():
        if not state["deleted"]:
            _safe(lambda: ec2.delete_vpn_connection(VpnConnectionId=vpn_id))

    ctx.on_cleanup(_cleanup)

    described = ec2.describe_vpn_connections(VpnConnectionIds=[vpn_id])["VpnConnections"][0]
    assert described["CustomerGatewayId"] == cgw_id, (
        f"expected CustomerGatewayId {cgw_id!r}, got {described['CustomerGatewayId']!r}"
    )
    assert described["VpnGatewayId"] == vgw_id, (
        f"expected VpnGatewayId {vgw_id!r}, got {described['VpnGatewayId']!r}"
    )
    assert described["State"] in ("pending", "available"), (
        f"expected state pending or available, got {described['State']!r}"
    )

    # success path: delete the VPN connection
    ec2.delete_vpn_connection(VpnConnectionId=vpn_id)
    state["deleted"] = True

    _poll_until(
        lambda: ec2.describe_vpn_connections(VpnConnectionIds=[vpn_id])["VpnConnections"][0]["State"],
        lambda s: s in ("deleting", "deleted"),
        timeout_s=60.0,
    )

    # distinct error boundary: a syntactically valid but nonexistent VPN connection id is rejected
    bogus_id = _mutate_id(vpn_id)
    code, msg = _client_error(lambda: ec2.delete_vpn_connection(VpnConnectionId=bogus_id))
    assert code == "InvalidVpnConnectionID.NotFound", f"expected InvalidVpnConnectionID.NotFound, got {code!r}"
    expected_msg = f"The vpnConnection ID '{bogus_id}' does not exist"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"


def _tag_spec(ctx, resource_type: str, prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-{prefix}-")}],
    }


def _client_error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidCustomerGatewayID.NotFound",
            "InvalidVpnConnectionID.NotFound",
            "InvalidVpnGatewayID.NotFound",
        ):
            raise


def _mutate_id(real_id: str) -> str:
    return real_id[:-1] + ("0" if real_id[-1] != "0" else "1")


def _vgw_state(ec2, vgw_id: str):
    try:
        described = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidVpnGatewayID.NotFound":
            return "pending"
        raise
    if not described:
        return "pending"
    return described[0]["State"]


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
