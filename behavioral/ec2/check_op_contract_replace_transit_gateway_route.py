"""op-contract-replace-transit-gateway-route."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "op-contract-replace-transit-gateway-route"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ReplaceTransitGatewayRoute flips a route from an attachment target to
    blackhole (success contract), and rejects an unknown route table."""
    ec2 = ctx.client("ec2")

    tgw_id = ec2.create_transit_gateway(
        Options={"DefaultRouteTableAssociation": "disable", "DefaultRouteTablePropagation": "disable"},
        TagSpecifications=_tags("transit-gateway", ctx.unique_name("sim2real-rtgr-")),
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id))
    try:
        _poll_until(lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
                    lambda s: s == "available", timeout_s=300, interval_s=10)
    except AssertionError:
        raise AssertionError(
            "transit gateway did not become available in time",
        )

    # This check doesn't need a dedicated VPC -- a transit gateway VPC
    # attachment works fine against any existing VPC/subnet. Creating a
    # brand-new VPC per check contends with the account's (often low, e.g.
    # 5) VPC-count limit when many checks run concurrently, and can hang
    # the check for its entire budget retrying CreateVpc. Prefer the account's default VPC (and one of its existing
    # subnets) to avoid that contention, only falling back to creating (and
    # later deleting) our own VPC/subnet if no default VPC or subnet is
    # available.
    vpc_id = _get_default_vpc(ec2, ctx=ctx)
    if vpc_id is None:
        vpc_id = _poll_until_success(
            lambda: ec2.create_vpc(CidrBlock="10.79.0.0/16",
                                    TagSpecifications=_tags("vpc", ctx.unique_name("sim2real-rtgr-")))["Vpc"]["VpcId"],
            retryable_codes={"VpcLimitExceeded"}, timeout_s=120, interval_s=10)
        ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))

    subnet_id = _get_any_subnet(ec2, vpc_id, ctx=ctx)
    if subnet_id is None:
        az = ec2.describe_availability_zones(Filters=[{"Name": "zone-name", "Values": ctx.network().availability_zones}])["AvailabilityZones"][0]["ZoneName"]
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock="10.79.1.0/24", AvailabilityZone=az,
            TagSpecifications=_tags("subnet", ctx.unique_name("sim2real-rtgr-")),
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))

    attach_id = ec2.create_transit_gateway_vpc_attachment(
        TransitGatewayId=tgw_id, VpcId=vpc_id, SubnetIds=[subnet_id],
        TagSpecifications=_tags("transit-gateway-attachment", ctx.unique_name("sim2real-rtgr-")),
    )["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]

    def _delete_attachment():
        ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attach_id)
        _poll_until(
            lambda: ec2.describe_transit_gateway_vpc_attachments(
                TransitGatewayAttachmentIds=[attach_id])["TransitGatewayVpcAttachments"][0]["State"],
            lambda s: s == "deleted", timeout_s=180, interval_s=5)
    ctx.on_cleanup(_delete_attachment)

    try:
        _poll_until(
            lambda: ec2.describe_transit_gateway_vpc_attachments(
                TransitGatewayAttachmentIds=[attach_id])["TransitGatewayVpcAttachments"][0]["State"],
            lambda s: s == "available", timeout_s=300, interval_s=10)
    except AssertionError:
        raise AssertionError(
            "transit gateway VPC attachment did not become available in time",
        )

    rtb_id = ec2.create_transit_gateway_route_table(
        TransitGatewayId=tgw_id, TagSpecifications=_tags("transit-gateway-route-table", ctx.unique_name("sim2real-rtgr-")),
    )["TransitGatewayRouteTable"]["TransitGatewayRouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=rtb_id))
    _poll_until(
        lambda: ec2.describe_transit_gateway_route_tables(
            TransitGatewayRouteTableIds=[rtb_id])["TransitGatewayRouteTables"][0]["State"],
        lambda s: s == "available", timeout_s=120, interval_s=5)

    dest_cidr = "10.201.0.0/24"
    created = ec2.create_transit_gateway_route(
        TransitGatewayRouteTableId=rtb_id, DestinationCidrBlock=dest_cidr,
        TransitGatewayAttachmentId=attach_id,
    )["Route"]
    assert created["State"] in ("active", "pending"), (
        f"expected active or pending route, got state {created['State']!r}")

    replaced = ec2.replace_transit_gateway_route(
        TransitGatewayRouteTableId=rtb_id, DestinationCidrBlock=dest_cidr, Blackhole=True,
    )["Route"]
    assert replaced["State"] == "blackhole", f"expected blackhole route, got {replaced}"
    assert replaced["DestinationCidrBlock"] == dest_cidr, (
        f"expected destination {dest_cidr!r}, got {replaced['DestinationCidrBlock']!r}")

    # SearchTransitGatewayRoutes can briefly lag the ReplaceTransitGatewayRoute
    # response we just asserted "blackhole" on above (the route table's search
    # index is updated asynchronously), so poll for it to converge instead of
    # asserting on a single snapshot.
    verify = _poll_until(
        lambda: ec2.search_transit_gateway_routes(
            TransitGatewayRouteTableId=rtb_id,
            Filters=[{"Name": "route-search.exact-match", "Values": [dest_cidr]}],
        )["Routes"],
        lambda routes: len(routes) == 1 and routes[0]["State"] == "blackhole",
        timeout_s=60, interval_s=5,
    )
    assert len(verify) == 1 and verify[0]["State"] == "blackhole", (
        f"expected exactly one blackhole route for {dest_cidr!r} in search results, got {verify!r}")

    # Transit gateway route tables reuse EC2's classic route-table
    # existence-check code path internally, so an unknown
    # TransitGatewayRouteTableId surfaces the same generic
    # InvalidRouteTableID.NotFound error used for VPC route tables --
    # there is no dedicated "InvalidTransitGatewayRouteTableId" error
    # family on real AWS.
    bogus_rtb_id = "tgw-rtb-1234567890abcdef0"
    code, message = _error_code_message(lambda: ec2.replace_transit_gateway_route(
        TransitGatewayRouteTableId=bogus_rtb_id, DestinationCidrBlock=dest_cidr, Blackhole=True))
    assert code == "InvalidRouteTableID.NotFound", (
        f"expected InvalidRouteTableID.NotFound, got {code}")
    expected_message = f"Transit Gateway Route Table {bogus_rtb_id} was deleted or does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


# ===== helpers =====

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


def _error_code_message(fn):
    from botocore.exceptions import ClientError
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _poll_until_success(fn, retryable_codes, timeout_s=120.0, interval_s=5.0):
    from botocore.exceptions import ClientError
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in retryable_codes:
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


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
