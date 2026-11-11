"""gateway-association-reflects-attached-vpc-cidr."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "gateway-association-reflects-attached-vpc-cidr"
GROUP = "gateway-associations"
SERVICES = ["directconnect", "ec2"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; EC2's own not-found codes pass."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _teardown_dx(undo, *not_found_phrases: str):
    """Like ``_teardown``, but keyed on the message: DirectConnectClientException covers every
    client error under one code, so only its not-found wording may be swallowed."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            msg = exc.response.get("Error", {}).get("Message", "")
            if any(p in msg for p in not_found_phrases):
                return
            raise

    return run_undo


def _poll(probe, predicate, *, timeout_s: float = 240.0, interval_s: float = 5.0, description: str = "condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s; last observed {last!r}")


def _teardown_detach_vgw(ec2, vpc_id: str, vgw_id: str):
    """Detach the VGW and wait for ``detached``: a fire-and-forget detach leaves the VGW delete
    that runs right after it in ``IncorrectState``, since detaching is asynchronous."""

    def run_undo() -> None:
        def state():
            atts = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"][0]["VpcAttachments"]
            return next((a["State"] for a in atts if a["VpcId"] == vpc_id), None)

        try:
            current = state()
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidVpnGatewayID.NotFound":
                return
            raise
        if current in (None, "detached"):
            return
        try:
            ec2.detach_vpn_gateway(VpcId=vpc_id, VpnGatewayId=vgw_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "InvalidVpnGatewayID.NotFound", "InvalidVpcID.NotFound", "InvalidVpnGatewayAttachment.NotFound",
            ):
                raise
        _poll(state, lambda s: s in (None, "detached"), timeout_s=180.0, description="VGW detach reaching detached")

    return run_undo


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Direct Connect gateway association advertises the attached VPC's CIDR as its
    allowedPrefixesToDirectConnectGateway, and disassociation clears it while the gateway
    the association pointed at keeps existing.
    """
    ec2 = ctx.client("ec2")
    dx = ctx.client("directconnect")

    cidr = "10.201.0.0/16"
    vpc_id = ec2.create_vpc(CidrBlock=cidr, TagSpecifications=[{
        "ResourceType": "vpc",
        "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-dxvpc-")}],
    }])["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))

    vgw_id = ec2.create_vpn_gateway(Type="ipsec.1", AmazonSideAsn=64513, TagSpecifications=[{
        "ResourceType": "vpn-gateway",
        "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-dxvgw-")}],
    }])["VpnGateway"]["VpnGatewayId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpn_gateway(VpnGatewayId=vgw_id), "InvalidVpnGatewayID.NotFound"))

    ec2.attach_vpn_gateway(VpcId=vpc_id, VpnGatewayId=vgw_id)
    ctx.on_cleanup(_teardown_detach_vgw(ec2, vpc_id, vgw_id))

    def attachment_state():
        atts = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"][0]["VpcAttachments"]
        return next((a["State"] for a in atts if a["VpcId"] == vpc_id), None)

    state = _poll(attachment_state, lambda s: s == "attached", description="VGW attachment reaching attached")
    assert state == "attached", f"expected the VGW attachment to reach attached, saw {state!r}"

    gw_id = dx.create_direct_connect_gateway(
        directConnectGatewayName=ctx.unique_name("sim2real-behav-dxgw-"), amazonSideAsn=64512
    )["directConnectGateway"]["directConnectGatewayId"]
    ctx.on_cleanup(lambda: dx.delete_direct_connect_gateway(directConnectGatewayId=gw_id))

    dx.create_direct_connect_gateway_association(directConnectGatewayId=gw_id, virtualGatewayId=vgw_id)
    ctx.on_cleanup(_teardown_dx(
        lambda: dx.delete_direct_connect_gateway_association(directConnectGatewayId=gw_id, virtualGatewayId=vgw_id),
        "does not exist", "No association exists between",
    ))

    def association():
        assocs = dx.describe_direct_connect_gateway_associations(directConnectGatewayId=gw_id)[
            "directConnectGatewayAssociations"
        ]
        return assocs[0] if assocs else None

    assoc = _poll(
        association, lambda a: a is not None and a["associationState"] == "associated",
        description="gateway association reaching associated",
    )
    assert assoc["associationState"] == "associated", (
        f"expected the association to reach associated, saw {assoc['associationState']!r}"
    )
    assert assoc["allowedPrefixesToDirectConnectGateway"] == [{"cidr": cidr}], (
        f"expected the gateway to advertise the attached VPC's own CIDR {cidr!r}, "
        f"got {assoc['allowedPrefixesToDirectConnectGateway']!r}"
    )
    assert assoc["associatedGateway"]["id"] == vgw_id, (
        f"expected associatedGateway.id {vgw_id!r}, got {assoc['associatedGateway']['id']!r}"
    )
    assert assoc["associatedGateway"]["type"] == "virtualPrivateGateway", (
        f"expected associatedGateway.type 'virtualPrivateGateway', got {assoc['associatedGateway']['type']!r}"
    )
    assert assoc["virtualGatewayId"] == vgw_id, (
        f"expected virtualGatewayId {vgw_id!r}, got {assoc['virtualGatewayId']!r}"
    )
    assert assoc["directConnectGatewayOwnerAccount"] == ctx.account, (
        f"expected directConnectGatewayOwnerAccount {ctx.account!r}, got {assoc['directConnectGatewayOwnerAccount']!r}"
    )

    dx.delete_direct_connect_gateway_association(directConnectGatewayId=gw_id, virtualGatewayId=vgw_id)
    assoc_gone = _poll(
        association, lambda a: a is None, description="gateway association clearing after disassociation",
    )
    assert assoc_gone is None, f"expected no association left for the gateway, saw {assoc_gone!r}"

    still_there = dx.describe_direct_connect_gateways(directConnectGatewayId=gw_id)["directConnectGateways"]
    assert still_there and still_there[0]["directConnectGatewayState"] == "available", (
        f"the disassociation should not have touched the gateway itself, saw {still_there!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
