"""op-contract-createVpnConnection."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-createVpnConnection"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpnConnection: success pairs a customer gateway with a virtual private gateway in
    pending state; a nonexistent CustomerGatewayId is rejected."""
    ec2 = ctx.client("ec2")

    cgw_id = ec2.create_customer_gateway(
        BgpAsn=65000,
        PublicIp="203.0.113.12",
        Type="ipsec.1",
        TagSpecifications=[{"ResourceType": "customer-gateway", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["CustomerGateway"]["CustomerGatewayId"]
    ctx.on_cleanup(lambda: _retry_while_in_use(lambda: ec2.delete_customer_gateway(CustomerGatewayId=cgw_id)))

    vgw_id = ec2.create_vpn_gateway(
        Type="ipsec.1",
        TagSpecifications=[{"ResourceType": "vpn-gateway", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )["VpnGateway"]["VpnGatewayId"]
    ctx.on_cleanup(lambda: _retry_while_in_use(lambda: ec2.delete_vpn_gateway(VpnGatewayId=vgw_id)))

    # The VPN gateway just created is not always immediately resolvable by CreateVpnConnection
    # (eventual consistency) -- poll describe_vpn_gateways until it is visible/available before
    # referencing it, instead of racing it.
    def _vgw_state():
        gws = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"]
        return gws[0]["State"] if gws else "unknown"

    _poll_until(_vgw_state, lambda s: s == "available", timeout_s=60, interval_s=3)

    resp = ec2.create_vpn_connection(
        Type="ipsec.1",
        CustomerGatewayId=cgw_id,
        VpnGatewayId=vgw_id,
        TagSpecifications=[{"ResourceType": "vpn-connection", "Tags": [{"Key": "sim2real", "Value": "1"}]}],
    )
    connection = resp["VpnConnection"]
    connection_id = connection["VpnConnectionId"]
    ctx.on_cleanup(lambda: ec2.delete_vpn_connection(VpnConnectionId=connection_id))

    # The CreateVpnConnection response can occasionally come back before the connection record
    # is fully populated (e.g. missing "Type"); re-fetch via DescribeVpnConnections, polling
    # briefly, rather than asserting against a possibly-partial create response.
    def _describe():
        return ec2.describe_vpn_connections(VpnConnectionIds=[connection_id])["VpnConnections"][0]

    connection = _poll_until(_describe, lambda c: "Type" in c, timeout_s=30, interval_s=2)

    assert connection["CustomerGatewayId"] == cgw_id
    assert connection["VpnGatewayId"] == vgw_id
    assert connection["State"] in ("pending", "available")
    assert connection["Type"] == "ipsec.1"

    # Error boundary: a nonexistent CustomerGatewayId is rejected.
    err = _client_error(
        lambda: ec2.create_vpn_connection(
            Type="ipsec.1",
            CustomerGatewayId="cgw-00000000000000000",
            VpnGatewayId=vgw_id,
        )
    )
    assert err.get("Code") == "InvalidCustomerGatewayID.NotFound", (
        f"expected InvalidCustomerGatewayID.NotFound, got {err!r}"
    )
    assert err.get("Message") == "The customerGateway ID 'cgw-00000000000000000' does not exist", (
        f"unexpected not-found message: {err!r}"
    )


def _retry_while_in_use(fn, timeout_s=300.0, interval_s=5.0):
    """Teardown: retry a gateway delete while a VPN connection deleted just before still holds it."""
    import time

    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "IncorrectState" or time.monotonic() > deadline:
                raise
        time.sleep(interval_s)


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    import time

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
