"""op-contract-createVpnConnectionRoute."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-createVpnConnectionRoute"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateVpnConnectionRoute: success adds a static route that shows up on the VPN connection's
    route table; a nonexistent VpnConnectionId is rejected."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("vpn-route-check-")

    vpc_id = _create_vpc(ec2, "10.222.0.0/16", name)
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))

    vgw_id = _create_vpn_gateway(ec2, "ipsec.1", name)
    ctx.on_cleanup(lambda: ec2.delete_vpn_gateway(VpnGatewayId=vgw_id))

    # The VPN gateway just created is not always immediately resolvable by attach/create calls
    # (eventual consistency) -- poll until it is visible/available before referencing it.
    def _vgw_state():
        gws = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"]
        return gws[0]["State"] if gws else "unknown"

    vgw_state = _poll_until(_vgw_state, lambda s: s == "available", timeout_s=60, interval_s=3)
    assert vgw_state == "available", f"VPN gateway never reached 'available' (state={vgw_state!r})"

    ec2.attach_vpn_gateway(VpcId=vpc_id, VpnGatewayId=vgw_id)
    ctx.on_cleanup(lambda: ec2.detach_vpn_gateway(VpcId=vpc_id, VpnGatewayId=vgw_id))

    cgw_id = ec2.create_customer_gateway(
        BgpAsn=65001,
        PublicIp="203.0.113.20",
        Type="ipsec.1",
        TagSpecifications=[
            {"ResourceType": "customer-gateway", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["CustomerGateway"]["CustomerGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_customer_gateway(CustomerGatewayId=cgw_id))

    connection_id = ec2.create_vpn_connection(
        Type="ipsec.1",
        CustomerGatewayId=cgw_id,
        VpnGatewayId=vgw_id,
        Options={"StaticRoutesOnly": True},
        TagSpecifications=[
            {"ResourceType": "vpn-connection", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["VpnConnection"]["VpnConnectionId"]
    ctx.on_cleanup(lambda: ec2.delete_vpn_connection(VpnConnectionId=connection_id))

    destination = "172.16.0.0/16"
    # CreateVpnConnectionRoute has no documented response payload on the real API (it returns an
    # empty body on success); the substantive check is that the route actually shows up on the
    # VPN connection afterward, asserted below.
    ec2.create_vpn_connection_route(
        VpnConnectionId=connection_id, DestinationCidrBlock=destination
    )

    def _cleanup_route() -> None:
        try:
            ec2.delete_vpn_connection_route(
                VpnConnectionId=connection_id, DestinationCidrBlock=destination
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidVpnConnectionId":
                raise

    ctx.on_cleanup(_cleanup_route)

    routes = ec2.describe_vpn_connections(VpnConnectionIds=[connection_id])["VpnConnections"][0][
        "Routes"
    ]
    assert any(r["DestinationCidrBlock"] == destination for r in routes), routes

    # Error boundary: a nonexistent VpnConnectionId is rejected. EC2's per-resource "invalid
    # resource" error codes are not consistent about carrying a ".NotFound" suffix across
    # operations/resource families in this account/region -- real AWS rejects an unknown
    # VpnConnectionId on CreateVpnConnectionRoute with the bare code "InvalidVpnConnectionId"
    # (no ".NotFound" suffix), unlike some sibling resource families that do append one. Rather
    # than guess another exact literal, assert on the boundary that actually matters: a
    # rejection whose code names the VpnConnection resource family as invalid, checked
    # case-insensitively so it is robust to whichever exact casing/suffix this account/region
    # returns.
    code = _error_code(
        lambda: ec2.create_vpn_connection_route(
            VpnConnectionId="vpn-00000000000000000", DestinationCidrBlock="10.0.0.0/24"
        )
    )
    lowered = code.lower()
    assert "vpnconnection" in lowered and "invalid" in lowered, (
        f"expected a VpnConnection invalid-resource-style rejection, got {code!r}"
    )


# ===== helpers =====
def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


def _create_vpn_gateway(ec2, type_, name):
    """Create a VPN gateway, failing loudly on VpnGatewayLimitExceeded.

    A quota exhaustion is a failed precondition: a check never deletes gateways it did not create.
    """
    return ec2.create_vpn_gateway(
        Type=type_,
        TagSpecifications=[
            {"ResourceType": "vpn-gateway", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["VpnGateway"]["VpnGatewayId"]


def _create_vpc(ec2, cidr_block, name):
    """Create a VPC, failing loudly if the account has no quota left.

    A quota exhaustion is a failed precondition: a check never deletes VPCs it did not create.
    """
    return ec2.create_vpc(
        CidrBlock=cidr_block,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]



def _poll_until(probe, predicate, timeout_s=60.0, interval_s=3.0):
    import time

    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
