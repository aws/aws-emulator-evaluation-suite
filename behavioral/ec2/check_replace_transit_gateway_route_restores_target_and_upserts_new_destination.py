"""replace-transit-gateway-route-restores-target-and-upserts-new-destination."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "replace-transit-gateway-route-restores-target-and-upserts-new-destination"
GROUP = 'transit-gateway'
SERVICES = ['ec2']


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ReplaceTransitGatewayRoute moves a route from an attachment to blackhole and back to the attachment
    (active), and for a destination the table never held creates a blackhole route; a later
    SearchTransitGatewayRoutes shows exactly both routes in those states."""
    ec2 = ctx.client("ec2")

    tgw_id = ec2.create_transit_gateway(
        Options={"DefaultRouteTableAssociation": "disable", "DefaultRouteTablePropagation": "disable"},
        TagSpecifications=_tags("transit-gateway", ctx.unique_name("sim2real-behav-rtgr-")),
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _delete_tgw_retrying(ec2, tgw_id))
    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=300,
        interval_s=10,
    )

    vpc_id = _get_default_vpc(ec2, ctx=ctx)
    if vpc_id is None:
        vpc_id = ec2.create_vpc(
            CidrBlock="10.83.0.0/16", TagSpecifications=_tags("vpc", ctx.unique_name("sim2real-behav-rtgr-"))
        )["Vpc"]["VpcId"]
        ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    subnet_id = _get_any_subnet(ec2, vpc_id, ctx=ctx)
    if subnet_id is None:
        az = ec2.describe_availability_zones(Filters=[{"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"][0]["ZoneName"]
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock="10.83.1.0/24", AvailabilityZone=az,
            TagSpecifications=_tags("subnet", ctx.unique_name("sim2real-behav-rtgr-")),
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    attach_id = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw_id, VpcId=vpc_id, SubnetIds=[subnet_id],
        TagSpecifications=_tags("transit-gateway-attachment", ctx.unique_name("sim2real-behav-rtgr-")),
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]

    def _delete_attachment():
        ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attach_id)
        _poll_until(
            lambda: ec2.describe_transit_gateway_vpc_attachments(
                TransitGatewayAttachmentIds=[attach_id])["TransitGatewayVpcAttachments"][0]["State"],
            lambda s: s == "deleted", timeout_s=180, interval_s=5)
    ctx.on_cleanup(_delete_attachment)
    _poll_until(
        lambda: ec2.describe_transit_gateway_vpc_attachments(
            TransitGatewayAttachmentIds=[attach_id])["TransitGatewayVpcAttachments"][0]["State"],
        lambda s: s == "available", timeout_s=300, interval_s=10)

    rtb_id = ec2.create_transit_gateway_route_table(
        TransitGatewayId=tgw_id, TagSpecifications=_tags("transit-gateway-route-table", ctx.unique_name("sim2real-behav-rtgr-")),
    )["TransitGatewayRouteTable"]["TransitGatewayRouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=rtb_id))
    _poll_until(
        lambda: ec2.describe_transit_gateway_route_tables(
            TransitGatewayRouteTableIds=[rtb_id])["TransitGatewayRouteTables"][0]["State"],
        lambda s: s == "available", timeout_s=120, interval_s=5)

    dest_a = "10.212.0.0/24"
    created = ec2.create_transit_gateway_route(
        TransitGatewayRouteTableId=rtb_id, DestinationCidrBlock=dest_a, TransitGatewayAttachmentId=attach_id,
    )["Route"]
    assert created["State"] in ("active", "pending"), (
        f"expected active or pending route, got state {created['State']!r}"
    )

    to_blackhole = ec2.replace_transit_gateway_route(
        TransitGatewayRouteTableId=rtb_id, DestinationCidrBlock=dest_a, Blackhole=True,
    )["Route"]
    assert to_blackhole["State"] == "blackhole", f"expected blackhole route, got {to_blackhole}"

    # NEW: replace the same destination back to an attachment target -- the route must become
    # active again and reference the attachment, not stay a blackhole.
    restored = ec2.replace_transit_gateway_route(
        TransitGatewayRouteTableId=rtb_id, DestinationCidrBlock=dest_a, TransitGatewayAttachmentId=attach_id,
    )["Route"]
    assert restored["State"] in ("active", "pending"), (
        f"expected the restored route to be active/pending, got {restored['State']!r}"
    )
    restored_atts = restored.get("TransitGatewayAttachments") or []
    assert any(a.get("TransitGatewayAttachmentId") == attach_id for a in restored_atts), (
        f"expected the restored route to reference attachment {attach_id!r}, got {restored_atts!r}"
    )
    verify_restored = _poll_until(
        lambda: ec2.search_transit_gateway_routes(
            TransitGatewayRouteTableId=rtb_id,
            Filters=[{"Name": "route-search.exact-match", "Values": [dest_a]}],
        )["Routes"],
        lambda routes: len(routes) == 1 and routes[0]["State"] == "active",
        timeout_s=60, interval_s=5,
    )
    assert verify_restored[0]["State"] == "active", (
        f"expected the restored route to settle active in search results, got {verify_restored!r}"
    )

    # NEW: replace a destination the table never held -- it is upserted (created), not rejected
    # for lacking a prior CreateTransitGatewayRoute.
    dest_b = "10.213.0.0/24"
    upserted = ec2.replace_transit_gateway_route(
        TransitGatewayRouteTableId=rtb_id, DestinationCidrBlock=dest_b, Blackhole=True,
    )["Route"]
    assert upserted["DestinationCidrBlock"] == dest_b, (
        f"expected destination {dest_b!r}, got {upserted['DestinationCidrBlock']!r}"
    )
    assert upserted["State"] == "blackhole", f"expected the upserted route to be blackhole, got {upserted}"

    static_routes = _poll_until(
        lambda: ec2.search_transit_gateway_routes(
            TransitGatewayRouteTableId=rtb_id,
            Filters=[{"Name": "type", "Values": ["static"]}],
        )["Routes"],
        lambda routes: len(routes) == 2,
        timeout_s=60, interval_s=5,
    )
    by_cidr = {r["DestinationCidrBlock"]: r for r in static_routes}
    assert set(by_cidr) == {dest_a, dest_b}, (
        f"expected exactly {{{dest_a!r}, {dest_b!r}}} as static routes, got {sorted(by_cidr)!r}"
    )
    assert by_cidr[dest_a]["State"] == "active", f"expected {dest_a!r} active, got {by_cidr[dest_a]!r}"
    assert by_cidr[dest_b]["State"] == "blackhole", f"expected {dest_b!r} blackhole, got {by_cidr[dest_b]!r}"


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


def _tags(resource_type: str, name: str) -> list[dict]:
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _get_default_vpc(ec2, *, ctx):
    vpcs = ec2.describe_vpcs(VpcIds=[ctx.network().vpc_id])["Vpcs"]
    defaults = [v for v in vpcs if v.get("IsDefault")]
    return defaults[0]["VpcId"] if defaults else None


def _get_any_subnet(ec2, vpc_id, *, ctx):
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    available = [s for s in subnets if s.get("State") == "available"]
    return available[0]["SubnetId"] if available else None


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. See the sibling
# checks in this suite for the full rationale.
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
