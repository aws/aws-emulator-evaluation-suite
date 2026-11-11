"""disassociate-transit-gateway-route-table-contract."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "disassociate-transit-gateway-route-table-contract"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DisassociateTransitGatewayRouteTable removes the link between an attachment and a
    transit gateway route table, and rejects a bogus route table ID with a distinct
    NotFound error."""
    ec2 = ctx.client("ec2")

    tgw = ec2.create_transit_gateway(
        Options={"DefaultRouteTableAssociation": "disable", "DefaultRouteTablePropagation": "disable"},
        TagSpecifications=[_tag_spec("transit-gateway", ctx.unique_name("sim2real-rttgw-"))],
    )["TransitGateway"]
    tgw_id = tgw["TransitGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id))

    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available", timeout_s=300.0, interval_s=10.0,
    )

    # The account's VPC quota is shared with everything else running concurrently; fall back to
    # an already-existing VPC/subnet rather than failing on a capacity error unrelated to
    # DisassociateTransitGatewayRouteTable's contract.
    vpc_id, subnet_id = _create_or_adopt_vpc_with_subnet(
        ec2, ctx, "10.219.0.0/16", "10.219.1.0/24",
        ctx.unique_name("sim2real-rtgvpc-"), ctx.unique_name("sim2real-rtgsubnet-"),
    )

    attach = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw_id, VpcId=vpc_id, SubnetIds=[subnet_id],
        TagSpecifications=[_tag_spec("transit-gateway-attachment", ctx.unique_name("sim2real-rtgattach-"))],
    )["TransitGatewayVpcAttachment"]
    attach_id = attach["TransitGatewayAttachmentId"]
    ctx.on_cleanup(lambda: _delete_attachment_and_wait(ec2, attach_id))

    _poll_until(
        lambda: ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attach_id])["TransitGatewayVpcAttachments"][0]["State"],
        lambda s: s == "available", timeout_s=300.0, interval_s=10.0,
    )

    route_table = ec2.create_transit_gateway_route_table(
        TransitGatewayId=tgw_id,
        TagSpecifications=[_tag_spec("transit-gateway-route-table", ctx.unique_name("sim2real-rtg-"))],
    )["TransitGatewayRouteTable"]
    rt_id = route_table["TransitGatewayRouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=rt_id))

    _poll_until(
        lambda: ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[rt_id])["TransitGatewayRouteTables"][0]["State"],
        lambda s: s == "available", timeout_s=120.0, interval_s=5.0,
    )

    ec2.associate_transit_gateway_route_table(TransitGatewayRouteTableId=rt_id, TransitGatewayAttachmentId=attach_id)

    def _assoc_state():
        resp = ec2.get_transit_gateway_route_table_associations(TransitGatewayRouteTableId=rt_id)
        for a in resp.get("Associations", []):
            if a.get("TransitGatewayAttachmentId") == attach_id:
                return a["State"]
        return None

    _poll_until(_assoc_state, lambda s: s == "associated", timeout_s=120.0, interval_s=5.0)

    resp = ec2.disassociate_transit_gateway_route_table(TransitGatewayRouteTableId=rt_id, TransitGatewayAttachmentId=attach_id)
    association = resp["Association"]
    assert association["TransitGatewayRouteTableId"] == rt_id, (
        f"expected route table {rt_id} in the disassociate response, got {association['TransitGatewayRouteTableId']!r}"
    )
    assert association["TransitGatewayAttachmentId"] == attach_id, (
        f"expected attachment {attach_id} in the disassociate response, got {association['TransitGatewayAttachmentId']!r}"
    )
    assert association["State"] in ("disassociating", "disassociated"), (
        f"expected disassociating/disassociated in the disassociate response, got {association['State']!r}"
    )

    # The mutating call's own response is not the terminal read: confirm at the
    # destination, through the independent GetTransitGatewayRouteTableAssociations read, that
    # the association actually reaches "disassociated" and is then dropped from the list --
    # not merely that the DisassociateTransitGatewayRouteTable response claimed it.
    final_state = _poll_until(
        _assoc_state, lambda s: s in ("disassociated", None), timeout_s=120.0, interval_s=5.0,
    )
    assert final_state in ("disassociated", None), (
        f"expected the independent read to show the association disassociated or removed, got {final_state!r}"
    )

    # NEGATIVE: a bogus TGW route table ID is rejected distinctly. Real TGW route-table IDs are
    # 17 hex characters after the prefix -- use a correctly-shaped-but-nonexistent one so the
    # rejection is a NotFound, not a format-validation error.
    bogus_rtb_id = "tgw-rtb-" + "0" * 17
    code, message = _error(lambda: ec2.disassociate_transit_gateway_route_table(
        TransitGatewayRouteTableId=bogus_rtb_id, TransitGatewayAttachmentId=attach_id,
    ))
    assert code == "InvalidRouteTableID.NotFound", f"unexpected error code for bogus TGW route table id: {code}"
    assert message == f"Transit Gateway Route Table {bogus_rtb_id} was deleted or does not exist.", f"unexpected message for bogus TGW route table id: {message!r}"


# ===== helpers =====
def _delete_attachment_and_wait(ec2, attach_id, timeout_s=600.0, interval_s=10.0):
    """Delete the VPC attachment and wait until it reads deleted: DeleteTransitGateway refuses
    with IncorrectState while any attachment is still deleting."""
    from botocore.exceptions import ClientError

    try:
        ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attach_id)
    except ClientError as exc:
        # The check may already have deleted it; the wait below still applies.
        if exc.response.get("Error", {}).get("Code") not in (
            "IncorrectState", "InvalidTransitGatewayAttachmentID.NotFound",
        ):
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        rows = ec2.describe_transit_gateway_vpc_attachments(
            TransitGatewayAttachmentIds=[attach_id]
        )["TransitGatewayVpcAttachments"]
        if not rows or rows[0]["State"] == "deleted":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"attachment {attach_id} still {rows[0]['State']!r} after {timeout_s}s")
        time.sleep(interval_s)


def _tag_spec(resource_type: str, name: str) -> dict:
    return {"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}


def _create_or_adopt_vpc_with_subnet(ec2, ctx, vpc_cidr, subnet_cidr, vpc_name, subnet_name, exclude=None):
    """Create a fresh VPC+subnet; if the account is at its VPC quota, adopt an existing VPC
    (distinct from ``exclude``) and one of its existing subnets instead."""
    vpc = ec2.create_vpc(CidrBlock=vpc_cidr, TagSpecifications=[_tag_spec("vpc", vpc_name)])["Vpc"]
    vpc_id = vpc["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=subnet_cidr, TagSpecifications=[_tag_spec("subnet", subnet_name)]
    )["Subnet"]
    subnet_id = subnet["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return vpc_id, subnet_id


def _error(fn):
    """Call fn(); return the ClientError's (code, message). An unexpected success raises, because
    a target accepting what real AWS refuses must not read as a plain code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


# EC2 network teardown: an asynchronously deleted dependent leaves its ENIs in the subnet / security
# group, so each delete retries DependencyViolation while they drain, inside one window shared by the
# check's network deletes and the suite's cleanup budget, then raises naming the ENIs still attached.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
