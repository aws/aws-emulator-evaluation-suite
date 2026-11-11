"""transit-gateway-route-table-propagation-produces-route-duplicate-enable-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "transit-gateway-route-table-propagation-produces-route-duplicate-enable-rejected"
GROUP = 'transit-gateway'
SERVICES = ['ec2']


@tags(
    "axis:rejection",
    "cap:c1",
    "cap:c4",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """EnableTransitGatewayRouteTablePropagation makes the VPC CIDR a propagated, active route in
    SearchTransitGatewayRoutes; enabling the same pair again fails with
    TransitGatewayRouteTablePropagation.Duplicate and adds no second entry; disable then enable works."""
    ec2 = ctx.client("ec2")

    vpc_name = ctx.unique_name("sim2real-behav-vpc-")
    vpc = ec2.create_vpc(
        CidrBlock="10.82.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": vpc_name}]}],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    vpc_cidr = vpc["CidrBlock"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet_id = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.82.1.0/24",
        AvailabilityZone=az,
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-subnet-")}]}],
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    tgw_id = ec2.create_transit_gateway(
        Options={"DefaultRouteTableAssociation": "disable", "DefaultRouteTablePropagation": "disable"},
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-tgw-")}]}],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _delete_tgw_retrying(ec2, tgw_id))
    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=300,
        interval_s=10,
    )

    att_id = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw_id,
        VpcId=vpc_id,
        SubnetIds=[subnet_id],
        TagSpecifications=[{"ResourceType": "transit-gateway-attachment", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-tgwa-")}]}],
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(lambda: _delete_attachment_and_wait(ec2, att_id))
    _poll_until(lambda: _describe_att(ec2, att_id)["State"], lambda s: s == "available", timeout_s=480)

    rt_id = ec2.create_transit_gateway_route_table(
        TransitGatewayId=tgw_id,
        TagSpecifications=[{"ResourceType": "transit-gateway-route-table", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-tgwrt-")}]}],
    )["TransitGatewayRouteTable"]["TransitGatewayRouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=rt_id))
    _poll_until(
        lambda: ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[rt_id])[
            "TransitGatewayRouteTables"
        ][0]["State"],
        lambda s: s == "available",
        timeout_s=120,
        interval_s=5,
    )

    enabled = ec2.enable_transit_gateway_route_table_propagation(
        TransitGatewayAttachmentId=att_id, TransitGatewayRouteTableId=rt_id
    )["Propagation"]
    assert enabled["State"] in ("pending", "enabled"), (
        f"expected pending/enabled immediately after enable, got {enabled.get('State')!r}"
    )

    _poll_until(
        lambda: _propagation_state(ec2, rt_id, att_id),
        lambda s: s == "enabled",
        timeout_s=120,
        interval_s=5,
    )

    # Positive: the propagated route is searchable with the attached VPC's own CIDR.
    found = _poll_until(
        lambda: _find_propagated_route(ec2, rt_id, vpc_cidr),
        lambda r: r is not None,
        timeout_s=120,
        interval_s=5,
    )
    assert found["Type"] == "propagated", f"expected Type propagated, got {found['Type']!r}"
    assert found["State"] == "active", f"expected State active, got {found['State']!r}"
    assert found["DestinationCidrBlock"] == vpc_cidr, (
        f"expected the propagated route's destination to be the VPC's own CIDR {vpc_cidr!r}, "
        f"got {found['DestinationCidrBlock']!r}"
    )

    # Negative: re-enabling the same (attachment, route table) pair is rejected.
    code = _error_code(
        lambda: ec2.enable_transit_gateway_route_table_propagation(
            TransitGatewayAttachmentId=att_id, TransitGatewayRouteTableId=rt_id
        )
    )
    assert code == "TransitGatewayRouteTablePropagation.Duplicate", (
        f"expected TransitGatewayRouteTablePropagation.Duplicate on a repeat enable, got {code!r}"
    )

    # Effect absent: the rejected duplicate enable created no second propagation entry.
    rows = ec2.get_transit_gateway_route_table_propagations(TransitGatewayRouteTableId=rt_id)[
        "TransitGatewayRouteTablePropagations"
    ]
    matches = [r for r in rows if r.get("TransitGatewayAttachmentId") == att_id]
    assert len(matches) == 1, (
        f"expected exactly one propagation entry for {att_id!r} after the rejected duplicate enable, "
        f"got {matches!r}"
    )

    # Positive control: disabling and then re-enabling still works -- only the no-op duplicate was blocked.
    ec2.disable_transit_gateway_route_table_propagation(
        TransitGatewayAttachmentId=att_id, TransitGatewayRouteTableId=rt_id
    )
    _poll_until(
        lambda: _propagation_state(ec2, rt_id, att_id),
        lambda s: s is None,
        timeout_s=120,
        interval_s=5,
    )
    ec2.enable_transit_gateway_route_table_propagation(
        TransitGatewayAttachmentId=att_id, TransitGatewayRouteTableId=rt_id
    )
    final_state = _poll_until(
        lambda: _propagation_state(ec2, rt_id, att_id),
        lambda s: s == "enabled",
        timeout_s=120,
        interval_s=5,
    )
    assert final_state == "enabled", f"re-enabling after a genuine disable did not reach enabled, got {final_state!r}"


def _delete_tgw_retrying(ec2, tgw_id, timeout_s=120.0, interval_s=5.0):
    """DeleteTransitGateway can transiently reject right after a dependent is deleted (the
    backend hasn't caught up yet); retry within a bound instead of leaking the gateway."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
            return
        except ClientError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _describe_att(ec2, att_id):
    return ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[att_id])[
        "TransitGatewayVpcAttachments"
    ][0]


def _propagation_state(ec2, rt_id, att_id):
    rows = ec2.get_transit_gateway_route_table_propagations(TransitGatewayRouteTableId=rt_id)[
        "TransitGatewayRouteTablePropagations"
    ]
    matches = [r for r in rows if r.get("TransitGatewayAttachmentId") == att_id]
    return matches[0]["State"] if matches else None


def _find_propagated_route(ec2, rt_id, cidr):
    resp = ec2.search_transit_gateway_routes(
        TransitGatewayRouteTableId=rt_id,
        Filters=[{"Name": "type", "Values": ["propagated"]}],
    )
    for route in resp.get("Routes", []):
        if route.get("DestinationCidrBlock") == cidr:
            return route
    return None


def _delete_attachment_and_wait(ec2, att_id, timeout_s=180.0, interval_s=5.0):
    try:
        ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=att_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayAttachmentID.NotFound":
            raise
        return
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            state = _describe_att(ec2, att_id)["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidTransitGatewayAttachmentID.NotFound":
                raise
            return
        if state == "deleted":
            return
        time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. See the sibling
# checks in this suite for the full rationale: an immediate DeleteSubnet/DeleteVpc can otherwise
# fail with DependencyViolation while an attachment's requester-managed ENIs are still detaching.
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
