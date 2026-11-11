"""op-contract-get-vpn-connection-device-sample-configuration."""
from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "op-contract-get-vpn-connection-device-sample-configuration"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetVpnConnectionDeviceSampleConfiguration: a config blob for a real connection, NotFound for a bogus one."""
    ec2 = ctx.client("ec2")

    device_types = ec2.get_vpn_connection_device_types().get("VpnConnectionDeviceTypes", [])
    if not device_types:
        raise AssertionError("no VPN connection device types returned by this account/region")
    device_type_id = device_types[0]["VpnConnectionDeviceTypeId"]

    cgw_id = _create_customer_gateway_with_retry(ec2, ctx)
    ctx.on_cleanup(lambda: ec2.delete_customer_gateway(CustomerGatewayId=cgw_id))

    vgw_id = ec2.create_vpn_gateway(
        Type="ipsec.1",
        TagSpecifications=[_tag_spec("vpn-gateway", ctx.unique_name("sim2real-vgw-"))],
    )["VpnGateway"]["VpnGatewayId"]
    ctx.on_cleanup(lambda: _delete_vpn_gateway(ec2, vgw_id))

    # A just-created VPN gateway is not always immediately resolvable by CreateVpnConnection
    # (eventual consistency) -- poll describe_vpn_gateways until it is "available" before
    # referencing it, instead of racing it.
    def _vgw_state():
        gws = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"]
        return gws[0]["State"] if gws else "unknown"

    _poll_until(_vgw_state, lambda s: s == "available", timeout_s=60, interval_s=3,
                description=f"VPN gateway {vgw_id!r} becoming 'available'")

    vpn_id = ec2.create_vpn_connection(
        CustomerGatewayId=cgw_id, VpnGatewayId=vgw_id, Type="ipsec.1",
        TagSpecifications=[_tag_spec("vpn-connection", ctx.unique_name("sim2real-vpn-"))],
    )["VpnConnection"]["VpnConnectionId"]
    ctx.on_cleanup(lambda: _delete_vpn_connection(ec2, vpn_id))

    resp = ec2.get_vpn_connection_device_sample_configuration(
        VpnConnectionId=vpn_id, VpnConnectionDeviceTypeId=device_type_id
    )
    assert "VpnConnectionDeviceSampleConfiguration" in resp, (
        f"expected VpnConnectionDeviceSampleConfiguration in the response, got keys {sorted(resp)!r}"
    )
    assert len(resp["VpnConnectionDeviceSampleConfiguration"]) > 0, (
        "expected a non-empty sample configuration document"
    )

    bogus_vpn_id = "vpn-00000000000000000"
    code, message = _error(
        lambda: ec2.get_vpn_connection_device_sample_configuration(
            VpnConnectionId=bogus_vpn_id, VpnConnectionDeviceTypeId=device_type_id
        )
    )
    # GetVpnConnectionDeviceSampleConfiguration does not follow the InvalidVpnConnectionID.NotFound
    # convention that ModifyVpnConnection and friends use for a well-formed but nonexistent id; it
    # reports the bare, suffix-less InvalidVpnConnectionId instead. Confirmed against real AWS.
    assert code == "InvalidVpnConnectionId", f"expected InvalidVpnConnectionId, got {code!r}"
    expected = f"The specified VpnConnection ({bogus_vpn_id}) for owner ({ctx.account}) does not exist"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


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


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


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
