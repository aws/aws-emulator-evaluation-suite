"""second-gateway-association-to-same-vgw-rejected-until-first-clears."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "second-gateway-association-to-same-vgw-rejected-until-first-clears"
GROUP = "gateway-associations"
SERVICES = ["directconnect", "ec2"]


def _error(fn) -> tuple[str, str]:
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A virtual private gateway already associated with one Direct Connect gateway refuses a
    second gateway's association, naming the virtual gateway; once the first association clears,
    the same second gateway associates to it successfully.
    """
    ec2 = ctx.client("ec2")
    dx = ctx.client("directconnect")

    vpc_id = ec2.create_vpc(CidrBlock="10.203.0.0/16", TagSpecifications=[{
        "ResourceType": "vpc",
        "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-dxvpc2-")}],
    }])["Vpc"]["VpcId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpc(VpcId=vpc_id), "InvalidVpcID.NotFound"))

    vgw_id = ec2.create_vpn_gateway(Type="ipsec.1", AmazonSideAsn=64513, TagSpecifications=[{
        "ResourceType": "vpn-gateway",
        "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-dxvgw2-")}],
    }])["VpnGateway"]["VpnGatewayId"]
    ctx.on_cleanup(_teardown(lambda: ec2.delete_vpn_gateway(VpnGatewayId=vgw_id), "InvalidVpnGatewayID.NotFound"))

    ec2.attach_vpn_gateway(VpcId=vpc_id, VpnGatewayId=vgw_id)
    ctx.on_cleanup(_teardown_detach_vgw(ec2, vpc_id, vgw_id))

    def attachment_state():
        atts = ec2.describe_vpn_gateways(VpnGatewayIds=[vgw_id])["VpnGateways"][0]["VpcAttachments"]
        return next((a["State"] for a in atts if a["VpcId"] == vpc_id), None)

    state = _poll(attachment_state, lambda s: s == "attached", description="VGW attachment reaching attached")
    assert state == "attached", f"expected the VGW attachment to reach attached, saw {state!r}"

    gw1_id = dx.create_direct_connect_gateway(
        directConnectGatewayName=ctx.unique_name("sim2real-behav-dxgw2a-"), amazonSideAsn=64512
    )["directConnectGateway"]["directConnectGatewayId"]
    ctx.on_cleanup(lambda: dx.delete_direct_connect_gateway(directConnectGatewayId=gw1_id))

    gw2_id = dx.create_direct_connect_gateway(
        directConnectGatewayName=ctx.unique_name("sim2real-behav-dxgw2b-"), amazonSideAsn=64512
    )["directConnectGateway"]["directConnectGatewayId"]
    ctx.on_cleanup(lambda: dx.delete_direct_connect_gateway(directConnectGatewayId=gw2_id))

    dx.create_direct_connect_gateway_association(directConnectGatewayId=gw1_id, virtualGatewayId=vgw_id)
    ctx.on_cleanup(_teardown_dx(
        lambda: dx.delete_direct_connect_gateway_association(directConnectGatewayId=gw1_id, virtualGatewayId=vgw_id),
        "does not exist", "No association exists between",
    ))

    def association(gw_id):
        assocs = dx.describe_direct_connect_gateway_associations(directConnectGatewayId=gw_id)[
            "directConnectGatewayAssociations"
        ]
        return assocs[0] if assocs else None

    assoc1 = _poll(
        lambda: association(gw1_id), lambda a: a is not None and a["associationState"] == "associated",
        description="first association reaching associated",
    )
    assert assoc1["associationState"] == "associated", (
        f"precondition: the first association should be associated, is {assoc1['associationState']!r}"
    )

    code, message = _error(
        lambda: dx.create_direct_connect_gateway_association(directConnectGatewayId=gw2_id, virtualGatewayId=vgw_id)
    )
    assert code == "DirectConnectClientException", (
        f"expected a second association to an already-associated VGW to be rejected "
        f"DirectConnectClientException, got {code!r}: {message!r}"
    )
    want = f"The maximum number of Direct Connect Gateway Associations to {vgw_id} has been reached"
    assert message == want, f"expected the refusal to name the VGW: expected {want!r}, got {message!r}"
    gw2_assoc_blocked = association(gw2_id)
    assert gw2_assoc_blocked is None, (
        f"the rejected call must not have created an association for the second gateway, saw {gw2_assoc_blocked!r}"
    )

    dx.delete_direct_connect_gateway_association(directConnectGatewayId=gw1_id, virtualGatewayId=vgw_id)
    _poll(
        lambda: association(gw1_id), lambda a: a is None,
        description="first association clearing after disassociation",
    )

    # The positive control: once the VGW's one slot frees up, the same second gateway succeeds.
    dx.create_direct_connect_gateway_association(directConnectGatewayId=gw2_id, virtualGatewayId=vgw_id)
    ctx.on_cleanup(_teardown_dx(
        lambda: dx.delete_direct_connect_gateway_association(directConnectGatewayId=gw2_id, virtualGatewayId=vgw_id),
        "does not exist", "No association exists between",
    ))
    assoc2 = _poll(
        lambda: association(gw2_id), lambda a: a is not None and a["associationState"] == "associated",
        description="second association reaching associated once the VGW is free",
    )
    assert assoc2["associationState"] == "associated", (
        f"expected the second gateway to associate once the VGW freed up, saw {assoc2['associationState']!r}"
    )

    dx.delete_direct_connect_gateway_association(directConnectGatewayId=gw2_id, virtualGatewayId=vgw_id)
    _poll(
        lambda: association(gw2_id), lambda a: a is None,
        description="second association clearing after disassociation",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
