"""transit-gateway-prefix-list-reference-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "transit-gateway-prefix-list-reference-lifecycle"
GROUP = "state-machine"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DryRun CreateTransitGatewayPrefixListReference creates nothing; the real create makes a
    blackhole reference, which ModifyTransitGatewayPrefixListReference points at a VPC attachment
    and back to blackhole."""
    ec2 = ctx.client("ec2")

    az = ec2.describe_availability_zones(
        Filters=[{"Name": "state", "Values": ["available"]}]
    )["AvailabilityZones"][0]["ZoneName"]

    tgw_name = ctx.unique_name("sim2real-tgw-")
    tgw_id = ec2.create_transit_gateway(
        Description=tgw_name,
        TagSpecifications=[
            {"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": tgw_name}]}
        ],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _delete_tgw(ec2, tgw_id))
    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])[
            "TransitGateways"
        ][0],
        lambda t: t["State"] == "available",
        timeout_s=600,
    )

    rt_id = ec2.create_transit_gateway_route_table(
        TransitGatewayId=tgw_id,
        TagSpecifications=[
            {"ResourceType": "transit-gateway-route-table", "Tags": [{"Key": "Name", "Value": tgw_name}]}
        ],
    )["TransitGatewayRouteTable"]["TransitGatewayRouteTableId"]
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=rt_id)
        )
    )
    _poll_until(
        lambda: ec2.describe_transit_gateway_route_tables(
            TransitGatewayRouteTableIds=[rt_id]
        )["TransitGatewayRouteTables"][0],
        lambda r: r["State"] == "available",
        timeout_s=120,
    )

    pl_name = ctx.unique_name("sim2real-pl-")
    pl_id = ec2.create_managed_prefix_list(
        PrefixListName=pl_name,
        MaxEntries=5,
        AddressFamily="IPv4",
        Entries=[],
        TagSpecifications=[
            {"ResourceType": "prefix-list", "Tags": [{"Key": "Name", "Value": pl_name}]}
        ],
    )["PrefixList"]["PrefixListId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_managed_prefix_list(PrefixListId=pl_id)))
    _poll_until(
        lambda: ec2.describe_managed_prefix_lists(PrefixListIds=[pl_id])["PrefixLists"][0],
        lambda p: p["State"] == "create-complete",
        timeout_s=60,
    )

    vpc_id = ec2.create_vpc(
        CidrBlock="10.235.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": tgw_name}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.235.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[
            {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": tgw_name}]}
        ],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))

    attach_id = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw_id,
        VpcId=vpc_id,
        SubnetIds=[subnet_id],
        TagSpecifications=[
            {"ResourceType": "transit-gateway-attachment", "Tags": [{"Key": "Name", "Value": tgw_name}]}
        ],
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(lambda: _delete_vpc_attachment(ec2, attach_id))
    _poll_until(
        lambda: ec2.describe_transit_gateway_vpc_attachments(
            TransitGatewayAttachmentIds=[attach_id]
        )["TransitGatewayVpcAttachments"][0],
        lambda a: a["State"] == "available",
        timeout_s=600,
    )

    # --- DryRun negative: no reference is created ---
    code, message = _error_code(
        lambda: ec2.create_transit_gateway_prefix_list_reference(
            TransitGatewayRouteTableId=rt_id,
            PrefixListId=pl_id,
            Blackhole=True,
            DryRun=True,
        )
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code!r}"
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"expected EC2's exact DryRunOperation message, got {message!r}"
    )
    refs = ec2.get_transit_gateway_prefix_list_references(
        TransitGatewayRouteTableId=rt_id
    )["TransitGatewayPrefixListReferences"]
    matching = [r for r in refs if r["PrefixListId"] == pl_id]
    assert matching == [], f"expected no reference after DryRun, found {matching!r}"

    # --- Positive control: the real create succeeds, as a blackhole route ---
    ec2.create_transit_gateway_prefix_list_reference(
        TransitGatewayRouteTableId=rt_id, PrefixListId=pl_id, Blackhole=True
    )
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ec2.delete_transit_gateway_prefix_list_reference(
                TransitGatewayRouteTableId=rt_id, PrefixListId=pl_id
            )
        )
    )

    def _find_ref():
        refs = ec2.get_transit_gateway_prefix_list_references(
            TransitGatewayRouteTableId=rt_id
        )["TransitGatewayPrefixListReferences"]
        return next((r for r in refs if r["PrefixListId"] == pl_id), None)

    ref = _poll_until(_find_ref, lambda r: r is not None and r["State"] == "available", timeout_s=120)
    assert ref["Blackhole"] is True, f"expected a blackhole reference on create, got {ref!r}"

    # --- Modify to route to the real attachment ---
    ec2.modify_transit_gateway_prefix_list_reference(
        TransitGatewayRouteTableId=rt_id,
        PrefixListId=pl_id,
        TransitGatewayAttachmentId=attach_id,
        Blackhole=False,
    )
    ref = _poll_until(
        _find_ref,
        lambda r: r is not None and r["State"] == "available" and r["Blackhole"] is False,
        timeout_s=120,
    )
    assert ref["TransitGatewayAttachment"]["TransitGatewayAttachmentId"] == attach_id, (
        f"expected reference to point at {attach_id!r}, got {ref.get('TransitGatewayAttachment')!r}"
    )

    # --- Modify back to blackhole ---
    ec2.modify_transit_gateway_prefix_list_reference(
        TransitGatewayRouteTableId=rt_id, PrefixListId=pl_id, Blackhole=True
    )
    ref = _poll_until(
        _find_ref,
        lambda r: r is not None and r["State"] == "available" and r["Blackhole"] is True,
        timeout_s=120,
    )
    assert ref.get("TransitGatewayAttachment") is None, (
        f"expected no attachment on a blackhole reference, got {ref.get('TransitGatewayAttachment')!r}"
    )


# ===== helpers =====
def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidNetworkInterfaceID.NotFound",
            "InvalidPrefixListID.NotFound",
            "InvalidRouteTableID.NotFound",
        ):
            raise


def _attachment_state(ec2, attach_id):
    atts = ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attach_id])[
        "TransitGatewayVpcAttachments"
    ]
    return atts[0]["State"] if atts else "deleted"


def _delete_vpc_attachment(ec2, attach_id) -> None:
    """Teardown: a pending attachment refuses delete, and an undeleted one holds an ENI in the
    subnet, so wait until it is deletable, delete it, and wait until it is gone."""
    _poll_until(
        lambda: _attachment_state(ec2, attach_id),
        lambda s: s in ("available", "failed", "rejected", "deleting", "deleted"),
        timeout_s=600,
        interval_s=10,
    )
    if _attachment_state(ec2, attach_id) not in ("deleting", "deleted"):
        ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attach_id)
    _poll_until(lambda: _attachment_state(ec2, attach_id), lambda s: s == "deleted", timeout_s=600, interval_s=10)


def _delete_tgw(ec2, tgw_id) -> None:
    """Teardown: retry while attachments finish deleting, so the transit gateway never leaks."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 600
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
        time.sleep(10)


def _error_code(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an over-permissive
    target cannot pass acceptance off as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


# EC2 network teardown: an ENI owner in this VPC releases its interfaces after its delete returns, so
# DeleteSubnet / DeleteSecurityGroup / DeleteVpc fail with DependencyViolation until they go. Wait and
# retry that code inside one window shared by the check's network deletes, then raise naming the ENIs.
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
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
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
