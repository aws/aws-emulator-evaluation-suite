"""modify-vpn-connection-options-on-deleted-connection-blocked."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "modify-vpn-connection-options-on-deleted-connection-blocked"
GROUP = "overly-permissive"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyVpnConnectionOptions on a deleted VPN connection, which DescribeVpnConnections still
    lists as 'deleted', fails InvalidVpnConnectionID.NotFound with its exact message; on a live
    connection it sets the local IPv4 network CIDR to 192.168.0.0/16.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-vpnmod-")

    vpc_id = ec2.create_vpc(CidrBlock="10.221.0.0/16", TagSpecifications=_tag_spec("vpc", name))["Vpc"][
        "VpcId"
    ]
    ctx.on_cleanup(lambda: _ignore_error(lambda: ec2.delete_vpc(VpcId=vpc_id)))

    customer_gateway_id = ec2.create_customer_gateway(
        Type="ipsec.1", PublicIp="203.0.113.1", BgpAsn=65000, TagSpecifications=_tag_spec("customer-gateway", name)
    )["CustomerGateway"]["CustomerGatewayId"]
    ctx.on_cleanup(
        lambda: _ignore_error(lambda: ec2.delete_customer_gateway(CustomerGatewayId=customer_gateway_id))
    )

    vpn_gateway_id = ec2.create_vpn_gateway(
        Type="ipsec.1", TagSpecifications=_tag_spec("vpn-gateway", name)
    )["VpnGateway"]["VpnGatewayId"]
    ctx.on_cleanup(lambda: _ignore_error(lambda: ec2.delete_vpn_gateway(VpnGatewayId=vpn_gateway_id)))
    ec2.attach_vpn_gateway(VpcId=vpc_id, VpnGatewayId=vpn_gateway_id)
    ctx.on_cleanup(lambda: _detach_vpn_gateway_and_wait(ec2, vpn_gateway_id, vpc_id))

    _poll_until(
        lambda: _vpn_gateway_attachment_state(ec2, vpn_gateway_id, vpc_id),
        lambda s: s == "attached",
        timeout_s=120,
        interval_s=5,
    )

    def _create_connection() -> str:
        cid = ec2.create_vpn_connection(
            Type="ipsec.1",
            CustomerGatewayId=customer_gateway_id,
            VpnGatewayId=vpn_gateway_id,
            Options={"StaticRoutesOnly": True},
            TagSpecifications=_tag_spec("vpn-connection", name),
        )["VpnConnection"]["VpnConnectionId"]
        _poll_until(
            lambda: _vpn_state(ec2, cid), lambda s: s == "available", timeout_s=600, interval_s=10
        )
        return cid

    # ---- Negative: create, delete, then try to modify the now-deleted connection ----
    vpn_connection_id = _create_connection()
    ctx.on_cleanup(lambda: _ignore_error(lambda: ec2.delete_vpn_connection(VpnConnectionId=vpn_connection_id)))

    ec2.delete_vpn_connection(VpnConnectionId=vpn_connection_id)
    _poll_until(
        lambda: _vpn_state(ec2, vpn_connection_id), lambda s: s == "deleted", timeout_s=180, interval_s=5
    )

    code, message = _expect_error(
        lambda: ec2.modify_vpn_connection_options(
            VpnConnectionId=vpn_connection_id, LocalIpv4NetworkCidr="192.168.0.0/16"
        )
    )
    # ModifyVpnConnectionOptions rejects a deleted VPN connection ID with
    # InvalidVpnConnectionID.NotFound, even though DescribeVpnConnections still
    # returns it in the terminal 'deleted' state (asserted below).
    assert code == "InvalidVpnConnectionID.NotFound", f"expected InvalidVpnConnectionID.NotFound, got {code!r}"
    assert message == f"The vpnConnection ID '{vpn_connection_id}' does not exist", message

    # Effect absence: the deleted connection's options were not changed.
    described = ec2.describe_vpn_connections(VpnConnectionIds=[vpn_connection_id])["VpnConnections"][0]
    assert described["State"] == "deleted", f"expected State 'deleted', got {described['State']!r}"
    got_cidr = described.get("Options", {}).get("LocalIpv4NetworkCidr")
    assert got_cidr != "192.168.0.0/16", f"expected LocalIpv4NetworkCidr unchanged, got {got_cidr!r}"

    # ---- Positive control: the same modification succeeds on a live VPN connection ----
    live_vpn_connection_id = _create_connection()
    ctx.on_cleanup(
        lambda: _ignore_error(lambda: ec2.delete_vpn_connection(VpnConnectionId=live_vpn_connection_id))
    )

    resp = ec2.modify_vpn_connection_options(
        VpnConnectionId=live_vpn_connection_id, LocalIpv4NetworkCidr="192.168.0.0/16"
    )
    got_resp_cidr = resp["VpnConnection"]["Options"]["LocalIpv4NetworkCidr"]
    assert got_resp_cidr == "192.168.0.0/16", f"expected LocalIpv4NetworkCidr '192.168.0.0/16', got {got_resp_cidr!r}"

    live_described = ec2.describe_vpn_connections(VpnConnectionIds=[live_vpn_connection_id])[
        "VpnConnections"
    ][0]
    got_described_cidr = live_described["Options"]["LocalIpv4NetworkCidr"]
    assert got_described_cidr == "192.168.0.0/16", (
        f"expected LocalIpv4NetworkCidr '192.168.0.0/16', got {got_described_cidr!r}"
    )


def _tag_spec(resource_type: str, name: str) -> list[dict[str, Any]]:
    return [
        {
            "ResourceType": resource_type,
            "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
        }
    ]


def _vpn_state(ec2, vpn_connection_id: str):
    conns = ec2.describe_vpn_connections(VpnConnectionIds=[vpn_connection_id])["VpnConnections"]
    return conns[0]["State"] if conns else None


def _vpn_gateway_attachment_state(ec2, vpn_gateway_id, vpc_id):
    attachments = ec2.describe_vpn_gateways(VpnGatewayIds=[vpn_gateway_id])["VpnGateways"][0].get(
        "VpcAttachments", []
    )
    for attachment in attachments:
        if attachment["VpcId"] == vpc_id:
            return attachment["State"]
    return None


def _detach_vpn_gateway_and_wait(ec2, vpn_gateway_id, vpc_id) -> None:
    try:
        ec2.detach_vpn_gateway(VpcId=vpc_id, VpnGatewayId=vpn_gateway_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidVpnGatewayID.NotFound":
            raise
        return
    _poll_until(
        lambda: _vpn_gateway_attachment_state(ec2, vpn_gateway_id, vpc_id),
        lambda state: state in (None, "detached"),
        timeout_s=120,
        interval_s=5,
    )


def _error_code(fn: Callable[[], Any]):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


def _expect_error(fn: Callable[[], Any]):
    """Call fn(); return its (code, message). Raise if it unexpectedly succeeds."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected rejection but call succeeded: {result!r}")


def _ignore_error(fn: Callable[[], Any]) -> None:
    _error_code(fn)


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
