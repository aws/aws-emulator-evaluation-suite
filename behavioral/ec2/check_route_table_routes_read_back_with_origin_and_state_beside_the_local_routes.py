"""route-table-routes-read-back-with-origin-and-state-beside-the-local-routes."""

from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "route-table-routes-read-back-with-origin-and-state-beside-the-local-routes"
GROUP = "vpc-networking"
SERVICES = ["ec2"]

VPC_CIDR = "10.232.0.0/16"
SUBNET_CIDR = "10.232.1.0/24"
_ASSOC_ID = re.compile(r"rtbassoc-[0-9a-f]{17}")
_ROUTE_KEYS = (
    "DestinationCidrBlock",
    "DestinationIpv6CidrBlock",
    "GatewayId",
    "EgressOnlyInternetGatewayId",
    "Origin",
    "State",
)
_ASSOC_KEYS = ("Main", "RouteTableId", "SubnetId", "AssociationState")


def _error(fn):
    """The (code, message) of the ClientError ``fn`` raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _teardown(undo, *not_found):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo():
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in not_found:
                raise

    return run_undo


def _poll(probe, done, *, what, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if done(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{what} not reached within {timeout_s}s; last read {last!r}")


def _tagspec(resource_type, name):
    return [{"ResourceType": resource_type, "Tags": [{"Key": "Name", "Value": name}]}]


def _destination(route):
    """A route's IPv4 or IPv6 destination, the key routes sort by."""
    return route.get("DestinationCidrBlock") or route.get("DestinationIpv6CidrBlock")


def _routes(table):
    """Each route's destination, target, origin and state, sorted by destination."""
    shaped = [{k: r[k] for k in _ROUTE_KEYS if k in r} for r in table["Routes"]]
    return sorted(shaped, key=_destination)


def _route(dest_key, dest, target_key, target, origin):
    return {dest_key: dest, target_key: target, "Origin": origin, "State": "active"}


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """A new route table holds only its local routes; routes to an internet gateway read back active

    A second ::/0 next hop is refused while the gateway route exists; associations read back and go.
    """
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-rtroutes-")

    vpc_id = ec2.create_vpc(
        CidrBlock=VPC_CIDR,
        AmazonProvidedIpv6CidrBlock=True,
        TagSpecifications=_tagspec("vpc", name),
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    vpc_v6 = _poll(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0].get(
            "Ipv6CidrBlockAssociationSet", []
        ),
        lambda a: len(a) == 1 and a[0]["Ipv6CidrBlockState"]["State"] == "associated",
        what=f"the IPv6 association of {vpc_id} in state associated",
    )[0]["Ipv6CidrBlock"]

    igw = ec2.create_internet_gateway(TagSpecifications=_tagspec("internet-gateway", name))[
        "InternetGateway"
    ]["InternetGatewayId"]
    ctx.on_cleanup(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw))
    ec2.attach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id)
    ctx.on_cleanup(
        _teardown(
            lambda: ec2.detach_internet_gateway(InternetGatewayId=igw, VpcId=vpc_id),
            "Gateway.NotAttached",
        )
    )

    eigw = ec2.create_egress_only_internet_gateway(
        VpcId=vpc_id, TagSpecifications=_tagspec("egress-only-internet-gateway", name)
    )["EgressOnlyInternetGateway"]["EgressOnlyInternetGatewayId"]
    ctx.on_cleanup(
        lambda: ec2.delete_egress_only_internet_gateway(EgressOnlyInternetGatewayId=eigw)
    )

    subnet_id = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock=SUBNET_CIDR, TagSpecifications=_tagspec("subnet", name)
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: ec2.delete_subnet(SubnetId=subnet_id))

    created = ec2.create_route_table(VpcId=vpc_id, TagSpecifications=_tagspec("route-table", name))[
        "RouteTable"
    ]
    rtb = created["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=rtb))
    local_v4 = _route("DestinationCidrBlock", VPC_CIDR, "GatewayId", "local", "CreateRouteTable")
    local_v6 = _route("DestinationIpv6CidrBlock", vpc_v6, "GatewayId", "local", "CreateRouteTable")
    want_local = sorted(
        [local_v4, local_v6],
        key=_destination,
    )
    assert _routes(created) == want_local, (
        f"a new route table must hold only the local routes {want_local}, got {_routes(created)}"
    )
    assert created["Associations"] == [], (
        f"a new route table has no association, got {created['Associations']}"
    )

    def _table():
        return ec2.describe_route_tables(RouteTableIds=[rtb])["RouteTables"][0]

    assert (
        ec2.create_route(RouteTableId=rtb, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw)[
            "Return"
        ]
        is True
    )
    assert (
        ec2.create_route(RouteTableId=rtb, DestinationIpv6CidrBlock="::/0", GatewayId=igw)["Return"]
        is True
    )
    want = sorted(
        want_local
        + [
            _route("DestinationCidrBlock", "0.0.0.0/0", "GatewayId", igw, "CreateRoute"),
            _route("DestinationIpv6CidrBlock", "::/0", "GatewayId", igw, "CreateRoute"),
        ],
        key=_destination,
    )
    assert _routes(_table()) == want, f"the route table reads {_routes(_table())}, expected {want}"

    # break exactly one thing: point ::/0 at a second target
    code, msg = _error(
        lambda: ec2.create_route(
            RouteTableId=rtb, DestinationIpv6CidrBlock="::/0", EgressOnlyInternetGatewayId=eigw
        )
    )
    assert (code, msg) == (
        "OperationNotPermitted",
        "There are existing ipv6 routes with next hop as internet Gateway.",
    ), f"a second ::/0 route answered {(code, msg)}"
    assert _routes(_table()) == want, (
        f"the refused route must leave the table unchanged, it reads {_routes(_table())}"
    )

    # restore: once the blocking route is gone, the identical call that was refused now succeeds.
    ec2.delete_route(RouteTableId=rtb, DestinationIpv6CidrBlock="::/0")
    assert ec2.create_route(
        RouteTableId=rtb, DestinationIpv6CidrBlock="::/0", EgressOnlyInternetGatewayId=eigw
    )["Return"] is True
    want_restored = sorted(
        want_local
        + [
            _route("DestinationCidrBlock", "0.0.0.0/0", "GatewayId", igw, "CreateRoute"),
            _route(
                "DestinationIpv6CidrBlock",
                "::/0",
                "EgressOnlyInternetGatewayId",
                eigw,
                "CreateRoute",
            ),
        ],
        key=_destination,
    )
    assert _routes(_table()) == want_restored, (
        f"the restored ::/0 route must now target {eigw}, the table reads {_routes(_table())}, "
        f"expected {want_restored}"
    )

    assoc_id = ec2.associate_route_table(RouteTableId=rtb, SubnetId=subnet_id)["AssociationId"]
    ctx.on_cleanup(
        _teardown(
            lambda: ec2.disassociate_route_table(AssociationId=assoc_id),
            "InvalidAssociationID.NotFound",
        )
    )
    assert _ASSOC_ID.fullmatch(assoc_id), f"the association id is {assoc_id!r}"
    assocs = _table()["Associations"]
    assert [a["RouteTableAssociationId"] for a in assocs] == [assoc_id], (
        f"the table lists associations {assocs}, expected exactly {assoc_id}"
    )
    want_assoc = {
        "Main": False,
        "RouteTableId": rtb,
        "SubnetId": subnet_id,
        "AssociationState": {"State": "associated"},
    }
    assert {k: assocs[0].get(k) for k in _ASSOC_KEYS} == want_assoc, (
        f"the association reads {assocs[0]}, expected {want_assoc}"
    )

    ec2.disassociate_route_table(AssociationId=assoc_id)
    assert _table()["Associations"] == [], (
        f"DisassociateRouteTable must remove the association: {_table()['Associations']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
