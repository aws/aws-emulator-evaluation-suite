"""op-contract-disable-transit-gateway-route-table-propagation."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-disable-transit-gateway-route-table-propagation"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Disabling propagation removes the attachment from the route table's
    propagation set; DryRun reports DryRunOperation without changing state."""
    ec2 = ctx.client("ec2")

    # Use the run's shared network so this check does not need a VPC of its
    # own (CreateVpc has a low per-account quota); create a dedicated
    # VPC/subnet only when the shared network is absent.
    vpc_id, subnet_id = _pick_default_vpc_and_subnet(ec2, ctx=ctx)
    if vpc_id is None:
        vpc_id = _create_with_retry(
            lambda: ec2.create_vpc(
                CidrBlock="10.71.0.0/16",
                TagSpecifications=[
                    {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-tgw-vpc-")}]}
                ],
            )["Vpc"]["VpcId"],
            retry_codes=("VpcLimitExceeded",),
            timeout_s=300.0,
            interval_s=15.0,
        )
        ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    if subnet_id is None:
        az = ec2.describe_availability_zones()["AvailabilityZones"][0]["ZoneName"]
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock="10.71.1.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-tgw-subnet-")}]}
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id)))

    tgw_id = _create_with_retry(
        lambda: _create_transit_gateway(ec2, ctx),
        retry_codes=("TransitGatewayLimitExceeded",),
        timeout_s=300.0 if ctx.time_left() is None else min(300.0, ctx.time_left()),
        interval_s=2.0,
    )
    ctx.on_cleanup(lambda: _teardown_transit_gateway(ec2, tgw_id))

    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda state: state == "available",
        timeout_s=240.0,
        interval_s=10.0,
    )

    attachment_id = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw_id,
        VpcId=vpc_id,
        SubnetIds=[subnet_id],
        TagSpecifications=[
            {
                "ResourceType": "transit-gateway-attachment",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-tgw-attach-")}],
            }
        ],
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(lambda: _delete_tgw_attachment(ec2, attachment_id))

    def _attachment_state():
        try:
            return ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attachment_id])[
                "TransitGatewayVpcAttachments"
            ][0]["State"]
        except ClientError as exc:
            # Read-after-create: the new attachment can briefly read as not found.
            if exc.response["Error"]["Code"] != "InvalidTransitGatewayAttachmentID.NotFound":
                raise
            return None

    _poll_until(
        _attachment_state,
        lambda state: state == "available",
        timeout_s=240.0,
        interval_s=10.0,
    )

    rtb_id = ec2.create_transit_gateway_route_table(
        TransitGatewayId=tgw_id,
        TagSpecifications=[
            {
                "ResourceType": "transit-gateway-route-table",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-tgw-rtb-")}],
            }
        ],
    )["TransitGatewayRouteTable"]["TransitGatewayRouteTableId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=rtb_id)))

    _poll_until(
        lambda: ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[rtb_id])[
            "TransitGatewayRouteTables"
        ][0]["State"],
        lambda state: state == "available",
        timeout_s=120.0,
        interval_s=5.0,
    )

    ec2.enable_transit_gateway_route_table_propagation(
        TransitGatewayRouteTableId=rtb_id, TransitGatewayAttachmentId=attachment_id
    )

    def _propagations():
        return ec2.get_transit_gateway_route_table_propagations(TransitGatewayRouteTableId=rtb_id)[
            "TransitGatewayRouteTablePropagations"
        ]

    _poll_until(
        _propagations,
        lambda props: any(p["TransitGatewayAttachmentId"] == attachment_id and p["State"] == "enabled" for p in props),
        timeout_s=120.0,
        interval_s=5.0,
    )

    # Error boundary: DryRun must report DryRunOperation without disabling propagation.
    code, message = _client_error(
        lambda: ec2.disable_transit_gateway_route_table_propagation(
            TransitGatewayRouteTableId=rtb_id, TransitGatewayAttachmentId=attachment_id, DryRun=True
        )
    )
    assert code == "DryRunOperation", code
    assert message == "Request would have succeeded, but DryRun flag is set.", (
        f"unexpected DryRunOperation message: {message!r}"
    )
    still_enabled = _propagations()
    assert any(p["TransitGatewayAttachmentId"] == attachment_id and p["State"] == "enabled" for p in still_enabled), (
        f"DryRun must not change propagation state; expected {attachment_id} still enabled, got {still_enabled}"
    )

    resp = ec2.disable_transit_gateway_route_table_propagation(
        TransitGatewayRouteTableId=rtb_id, TransitGatewayAttachmentId=attachment_id
    )
    assert resp["Propagation"]["TransitGatewayAttachmentId"] == attachment_id, resp

    _poll_until(
        _propagations,
        lambda props: not any(p["TransitGatewayAttachmentId"] == attachment_id and p["State"] == "enabled" for p in props),
        timeout_s=120.0,
        interval_s=5.0,
    )


# ===== helpers =====
def _create_transit_gateway(ec2, ctx):
    name = ctx.unique_name("sim2real-tgw-")
    return ec2.create_transit_gateway(
        Description=name,
        Options={"DefaultRouteTableAssociation": "disable", "DefaultRouteTablePropagation": "disable"},
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
    )["TransitGateway"]["TransitGatewayId"]


def _pick_default_vpc_and_subnet(ec2, *, ctx):
    """Prefer the account's existing shared network (and one of its
    already-provisioned subnets) over allocating a brand-new VPC — the
    shared network costs nothing against the per-account VPC limit and is
    perfectly adequate for hosting a TGW VPC attachment."""
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None, None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "state", "Values": ["available"]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    )["Subnets"]
    if not subnets:
        return vpc_id, None
    subnet = max(subnets, key=lambda s: s.get("AvailableIpAddressCount", 0))
    return vpc_id, subnet["SubnetId"]


def _create_with_retry(fn, retry_codes, timeout_s=150.0, interval_s=20.0):
    """Retry a create-style call while the account is at a transient resource-limit ceiling;
    re-raise once the timeout is exhausted or the error is not one of the retry codes."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            if e.response["Error"]["Code"] in retry_codes and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _client_error(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because a
    target ACCEPTING a call real AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidNetworkInterfaceID.NotFound",
            "InvalidRouteTableID.NotFound",
            "InvalidTransitGatewayAttachmentID.NotFound",
        ):
            raise


# Transit gateway deletes are ASYNC: DeleteTransitGatewayVpcAttachment returns while the attachment
# is still "deleting", and DeleteTransitGateway is refused until every attachment is gone. So the
# teardown deletes the gateway's attachments and route tables by discovery, WAITS for the
# attachments to reach "deleted", and retries the gateway delete under one bounded budget.
_TGW_TEARDOWN_S = 600.0
_ATTACHMENT_DELETE_S = 240.0


def _delete_tgw_attachment(ec2, attachment_id: str) -> None:
    """AWS refuses the delete with IncorrectState while the attachment is still pending: retry that."""
    deadline = time.monotonic() + _ATTACHMENT_DELETE_S
    while True:
        try:
            ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attachment_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidTransitGatewayAttachmentID.NotFound":
                return
            if code != "IncorrectState" or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _tgw_live_attachments(ec2, tgw_id):
    from botocore.exceptions import ClientError

    try:
        atts = ec2.describe_transit_gateway_attachments(
            Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}]
        )["TransitGatewayAttachments"]
    except ClientError:
        return []
    return [a for a in atts if a.get("State") not in ("deleted", "failed", "rejected")]


def _teardown_transit_gateway(ec2, tgw_id: str) -> None:
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + _TGW_TEARDOWN_S
    for att in _tgw_live_attachments(ec2, tgw_id):
        if att.get("State") != "deleting" and att.get("ResourceType") == "vpc":
            _delete_tgw_attachment(ec2, att["TransitGatewayAttachmentId"])
    while _tgw_live_attachments(ec2, tgw_id) and time.monotonic() < deadline:
        time.sleep(2)
    rtbs = ec2.describe_transit_gateway_route_tables(
        Filters=[{"Name": "transit-gateway-id", "Values": [tgw_id]}]
    )["TransitGatewayRouteTables"]
    for rtb in rtbs:
        if not rtb.get("DefaultAssociationRouteTable") and rtb.get("State") not in ("deleted", "deleting"):
            _safe(lambda r=rtb: ec2.delete_transit_gateway_route_table(
                TransitGatewayRouteTableId=r["TransitGatewayRouteTableId"]
            ))
    while True:
        try:
            ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code == "InvalidTransitGatewayID.NotFound":
                return
            if code not in ("IncorrectState", "DependencyViolation") or time.monotonic() >= deadline:
                raise RuntimeError(f"delete_transit_gateway({tgw_id}): {code}") from exc
        time.sleep(2)


# EC2 network deletes wait for AWS-managed ENIs to leave: a resource in this VPC deletes asynchronously,
# so DeleteSubnet/DeleteSecurityGroup/DeleteVpc fail with DependencyViolation until its ENIs go. Retry
# that code to one deadline shared by the check's network deletes, then raise naming the ENIs left.
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
