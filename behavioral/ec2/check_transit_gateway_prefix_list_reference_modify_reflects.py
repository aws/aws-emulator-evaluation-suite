"""transit-gateway-prefix-list-reference-modify-reflects."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transit-gateway-prefix-list-reference-modify-reflects"
GROUP = "data-plane"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyTransitGatewayPrefixListReference changes the target attachment and the change is visible on the next describe."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgwplr-")

    tgw_id = ec2.create_transit_gateway(
        Description=name,
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _delete_tgw(ec2, tgw_id))
    _wait_tgw_available(ec2, tgw_id)

    route_table_id = ec2.create_transit_gateway_route_table(
        TransitGatewayId=tgw_id,
        TagSpecifications=[
            {"ResourceType": "transit-gateway-route-table", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["TransitGatewayRouteTable"]["TransitGatewayRouteTableId"]
    ctx.on_cleanup(lambda: _delete_route_table(ec2, route_table_id))

    vpc1_id, subnet1_id = _create_vpc_and_subnet(ctx, ec2, name + "1", "10.181.0.0/16", "10.181.1.0/24")
    vpc2_id, subnet2_id = _create_vpc_and_subnet(ctx, ec2, name + "2", "10.182.0.0/16", "10.182.1.0/24")

    attach1_id = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw_id,
        VpcId=vpc1_id,
        SubnetIds=[subnet1_id],
        TagSpecifications=[
            {"ResourceType": "transit-gateway-attachment", "Tags": [{"Key": "Name", "Value": name + "1"}]}
        ],
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(lambda: _safe_delete_attachment(ec2, attach1_id))
    attach2_id = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw_id,
        VpcId=vpc2_id,
        SubnetIds=[subnet2_id],
        TagSpecifications=[
            {"ResourceType": "transit-gateway-attachment", "Tags": [{"Key": "Name", "Value": name + "2"}]}
        ],
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(lambda: _safe_delete_attachment(ec2, attach2_id))

    _wait_attachment_available(ec2, attach1_id)
    _wait_attachment_available(ec2, attach2_id)

    prefix_list_id = ec2.create_managed_prefix_list(
        PrefixListName=name,
        MaxEntries=1,
        AddressFamily="IPv4",
        Entries=[{"Cidr": "198.51.100.0/24", "Description": "sim2real-behav"}],
        TagSpecifications=[{"ResourceType": "prefix-list", "Tags": [{"Key": "Name", "Value": name}]}],
    )["PrefixList"]["PrefixListId"]
    ctx.on_cleanup(lambda: ec2.delete_managed_prefix_list(PrefixListId=prefix_list_id))
    _wait_prefix_list_state(ec2, prefix_list_id, "create-complete")

    ec2.create_transit_gateway_prefix_list_reference(
        TransitGatewayRouteTableId=route_table_id,
        PrefixListId=prefix_list_id,
        TransitGatewayAttachmentId=attach1_id,
    )
    ctx.on_cleanup(lambda: _safe_delete_reference(ec2, route_table_id, prefix_list_id))

    ref = _wait_reference_state(ec2, route_table_id, prefix_list_id, "available")
    assert ref["TransitGatewayAttachment"]["TransitGatewayAttachmentId"] == attach1_id, (
        f"prefix list reference did not settle on the initial attachment {attach1_id!r}: {ref!r}"
    )

    ec2.modify_transit_gateway_prefix_list_reference(
        TransitGatewayRouteTableId=route_table_id,
        PrefixListId=prefix_list_id,
        TransitGatewayAttachmentId=attach2_id,
    )

    updated = _wait_reference_state(ec2, route_table_id, prefix_list_id, "available")
    assert updated["TransitGatewayAttachment"]["TransitGatewayAttachmentId"] == attach2_id, (
        "prefix list reference still points at the original attachment after modify"
    )

    ec2.delete_transit_gateway_prefix_list_reference(
        TransitGatewayRouteTableId=route_table_id, PrefixListId=prefix_list_id
    )
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        if _find_reference(ec2, route_table_id, prefix_list_id) is None:
            break
        time.sleep(3)
    else:
        raise AssertionError("deleted prefix list reference is still listed")

    code, message = _error_code(
        lambda: ec2.modify_transit_gateway_prefix_list_reference(
            TransitGatewayRouteTableId=route_table_id,
            PrefixListId=prefix_list_id,
            TransitGatewayAttachmentId=attach2_id,
        )
    )
    assert code == "InvalidPrefixListID.NotFound", (
        f"modify on a deleted prefix list reference should fail InvalidPrefixListID.NotFound, got {code!r}"
    )
    expected = (
        f"PrefixListId {prefix_list_id} is not referenced in Transit Gateway Route Table {route_table_id}."
    )
    assert message == expected, f"expected EC2's exact unreferenced-prefix-list message {expected!r}, got {message!r}"


# ===== helpers =====


def _create_vpc_and_subnet(ctx, ec2, name, vpc_cidr, subnet_cidr):
    vpc_id = ec2.create_vpc(
        CidrBlock=vpc_cidr,
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    _wait_vpc_available(ec2, vpc_id)
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=subnet_cidr,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return vpc_id, subnet_id


def _wait_vpc_available(ec2, vpc_id, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
        if vpc["State"] == "available":
            return
        time.sleep(2)
    raise AssertionError("VPC never became available")


def _wait_tgw_available(ec2, tgw_id, timeout_s=300.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        tgw = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]
        if tgw["State"] == "available":
            return
        if tgw["State"] in ("deleting", "deleted"):
            raise AssertionError(f"transit gateway entered unexpected state {tgw['State']}")
        time.sleep(2)
    raise AssertionError("transit gateway never became available")


def _wait_attachment_available(ec2, attachment_id, timeout_s=300.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        att = ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attachment_id])[
            "TransitGatewayVpcAttachments"
        ][0]
        if att["State"] == "available":
            return
        time.sleep(2)
    raise AssertionError("transit gateway VPC attachment never became available")


def _wait_prefix_list_state(ec2, prefix_list_id, state, timeout_s=60.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        pl = ec2.describe_managed_prefix_lists(PrefixListIds=[prefix_list_id])["PrefixLists"][0]
        if pl["State"] == state:
            return
        time.sleep(3)
    raise AssertionError(f"managed prefix list never reached state {state!r}")


def _find_reference(ec2, route_table_id, prefix_list_id):
    resp = ec2.get_transit_gateway_prefix_list_references(TransitGatewayRouteTableId=route_table_id)
    for r in resp.get("TransitGatewayPrefixListReferences", []):
        if r["PrefixListId"] == prefix_list_id:
            return r
    return None


def _wait_reference_state(ec2, route_table_id, prefix_list_id, state, timeout_s=120.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        ref = _find_reference(ec2, route_table_id, prefix_list_id)
        if ref is not None and ref["State"] == state:
            return ref
        time.sleep(5)
    raise AssertionError(f"prefix list reference never reached state {state!r}")


def _attachment_state(ec2, attachment_id):
    atts = ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attachment_id])[
        "TransitGatewayVpcAttachments"
    ]
    return atts[0]["State"] if atts else "deleted"


def _wait_attachment_state(ec2, attachment_id, states, timeout_s=600.0):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        state = _attachment_state(ec2, attachment_id)
        if state in states:
            return state
        time.sleep(2)
    raise AssertionError(f"transit gateway VPC attachment never reached {states!r}")


def _safe_delete_attachment(ec2, attachment_id):
    """Teardown: a pending attachment refuses delete and a deleting one still blocks the transit
    gateway's delete, so wait until it is deletable, delete it, and wait until it is gone."""
    # The teardowns in this file (2 x 200 s attachments, 160 s network, 100 s route table, 180 s
    # transit gateway) add up to 840 s of the suite's 900 s cleanup budget.
    deadline = time.monotonic() + 200.0
    state = _wait_attachment_state(
        ec2,
        attachment_id,
        ("available", "failed", "rejected", "deleting", "deleted"),
        timeout_s=200.0,
    )
    if state not in ("deleting", "deleted"):
        try:
            ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attachment_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidTransitGatewayAttachmentID.NotFound":
                raise
    _wait_attachment_state(
        ec2, attachment_id, ("deleted",), timeout_s=max(0.0, deadline - time.monotonic())
    )


def _delete_route_table(ec2, route_table_id):
    """Teardown: delete the route table, retrying every 2 s while it is in an incorrect state."""
    deadline = time.monotonic() + 100.0
    while True:
        try:
            ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=route_table_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidRouteTableID.NotFound":
                return
            if code != "IncorrectState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _delete_tgw(ec2, tgw_id):
    """Teardown: retry while attachments finish deleting, so the transit gateway never leaks."""
    deadline = time.monotonic() + 180
    while True:
        try:
            ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidTransitGatewayID.NotFound":
                return
            if code not in ("IncorrectState", "DependencyViolation") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _safe_delete_reference(ec2, route_table_id, prefix_list_id):
    try:
        ec2.delete_transit_gateway_prefix_list_reference(
            TransitGatewayRouteTableId=route_table_id, PrefixListId=prefix_list_id
        )
    except ClientError as exc:
        # A reference the check already deleted reads InvalidPrefixListID.NotFound.
        gone = ("InvalidRouteTableID.NotFound", "InvalidPrefixListID.NotFound")
        if exc.response["Error"]["Code"] not in gone:
            raise


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


# EC2 network teardown: an ENI owner in this VPC releases its interfaces after its delete returns, so
# DeleteSubnet / DeleteSecurityGroup / DeleteVpc fail with DependencyViolation until they go. Wait and
# retry that code inside one window shared by the check's network deletes, then raise naming the ENIs.
_NET_TEARDOWN_S = 630.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    # The transit gateway teardowns take most of the 900 s cleanup budget, so the network window
    # is capped here rather than at _NET_TEARDOWN_S.
    budget = min(_NET_TEARDOWN_S, 160.0)
    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + budget)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
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
                        f"{op}({ident}): DependencyViolation after {budget}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


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
