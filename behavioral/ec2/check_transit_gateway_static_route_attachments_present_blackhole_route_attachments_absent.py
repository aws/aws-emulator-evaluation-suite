"""transit-gateway-static-route-attachments-present-blackhole-route-attachments-absent."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transit-gateway-static-route-attachments-present-blackhole-route-attachments-absent"
GROUP = "transit-gateway"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A route to a real attachment is Type=static naming that attachment; a blackhole route is
    also Type=static but OMITS the TransitGatewayAttachments key (not an empty list), and
    SearchTransitGatewayRoutes filtered by type=static finds both."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgwrtsb-")

    vpc_id, subnet_id = _create_vpc_and_subnet(ctx, ec2, name)
    tgw_id = _create_tgw(ctx, ec2, name)
    attachment_id = _create_vpc_attachment(ctx, ec2, tgw_id, vpc_id, subnet_id, name)
    _wait_attachment_state(ec2, attachment_id, "available", timeout_s=240.0)
    route_table_id = _create_route_table(ctx, ec2, tgw_id, name)

    static_cidr = "10.218.0.0/16"
    blackhole_cidr = "10.219.0.0/16"

    static_created = _retry_on_incorrect_state(
        lambda: ec2.create_transit_gateway_route(
            TransitGatewayRouteTableId=route_table_id,
            DestinationCidrBlock=static_cidr,
            TransitGatewayAttachmentId=attachment_id,
        )
    )["Route"]
    assert static_created["Type"] == "static", f"expected Type=static, got {static_created['Type']!r}"
    assert static_created["State"] in ("pending", "active"), (
        f"expected pending/active, got {static_created['State']!r}"
    )
    static_atts = static_created.get("TransitGatewayAttachments") or []
    assert any(a["TransitGatewayAttachmentId"] == attachment_id for a in static_atts), (
        f"expected the static route's response to carry attachment {attachment_id!r}, got {static_atts}"
    )

    blackhole_created = _retry_on_incorrect_state(
        lambda: ec2.create_transit_gateway_route(
            TransitGatewayRouteTableId=route_table_id,
            DestinationCidrBlock=blackhole_cidr,
            Blackhole=True,
        )
    )["Route"]
    # Type is static-vs-propagated (how the route was learned), not static-vs-blackhole
    # (whether it forwards) -- a manually created blackhole route is still Type=static.
    assert blackhole_created["State"] == "blackhole", (
        f"expected State=blackhole, got {blackhole_created['State']!r}"
    )
    assert "TransitGatewayAttachments" not in blackhole_created, (
        f"a blackhole route carries no attachment, so the key must be ABSENT, got "
        f"{blackhole_created.get('TransitGatewayAttachments')!r}"
    )

    # Independent read of both routes together, settled.
    static_route = _poll(
        lambda: _find_route(ec2, route_table_id, static_cidr),
        lambda r: r is not None and r["State"] == "active",
        timeout_s=60.0,
    )
    assert static_route["Type"] == "static", f"expected Type=static on read-back, got {static_route['Type']!r}"
    static_atts = static_route.get("TransitGatewayAttachments") or []
    assert any(a["TransitGatewayAttachmentId"] == attachment_id for a in static_atts), (
        f"expected read-back static route to carry attachment {attachment_id!r}, got {static_atts}"
    )

    blackhole_route = _find_route(ec2, route_table_id, blackhole_cidr)
    assert blackhole_route is not None, "blackhole route disappeared on independent read"
    assert blackhole_route["State"] == "blackhole", (
        f"expected State=blackhole on read-back, got {blackhole_route['State']!r}"
    )
    assert "TransitGatewayAttachments" not in blackhole_route, (
        f"independent read of the blackhole route must also omit the key, got "
        f"{blackhole_route.get('TransitGatewayAttachments')!r}"
    )

    # type=static is "manually created", not "forwards traffic" -- it matches BOTH the
    # attachment route and the blackhole route, since the service's Type axis
    # (static vs propagated-from-BGP) is independent of the State axis (active vs
    # blackhole) that the two routes actually differ on.
    type_filtered = _poll(
        lambda: ec2.search_transit_gateway_routes(
            TransitGatewayRouteTableId=route_table_id, Filters=[{"Name": "type", "Values": ["static"]}]
        )["Routes"],
        lambda rows: {r["DestinationCidrBlock"] for r in rows} >= {static_cidr, blackhole_cidr},
        timeout_s=60.0,
    )
    found_cidrs = {r["DestinationCidrBlock"] for r in type_filtered}
    assert static_cidr in found_cidrs, f"expected {static_cidr!r} among type=static results, got {found_cidrs}"
    assert blackhole_cidr in found_cidrs, (
        f"expected the blackhole route to ALSO be Type=static, got {found_cidrs}"
    )

    delete_resp = ec2.delete_transit_gateway_route(
        TransitGatewayRouteTableId=route_table_id, DestinationCidrBlock=blackhole_cidr
    )
    assert delete_resp["Route"]["State"] == "deleted", f"expected deleted, got {delete_resp['Route']['State']!r}"
    deleted_cidrs = _poll(
        lambda: {
            r["DestinationCidrBlock"]
            for r in ec2.search_transit_gateway_routes(
                TransitGatewayRouteTableId=route_table_id,
                Filters=[{"Name": "route-search.exact-match", "Values": [blackhole_cidr]}],
            )["Routes"]
        },
        lambda cidrs: blackhole_cidr not in cidrs,
        timeout_s=60.0,
    )
    assert blackhole_cidr not in deleted_cidrs, f"deleted blackhole route still searchable: {deleted_cidrs}"


# ===== helpers =====

def _poll(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float = 5.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _best_effort(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidSubnetID.NotFound",
            "InvalidTransitGatewayAttachmentID.NotFound",
            "InvalidTransitGatewayID.NotFound",
            "InvalidVpcID.NotFound",
        ):
            raise


def _find_route(ec2, route_table_id: str, cidr: str) -> dict | None:
    rows = ec2.search_transit_gateway_routes(
        TransitGatewayRouteTableId=route_table_id,
        Filters=[{"Name": "route-search.exact-match", "Values": [cidr]}],
    )["Routes"]
    return next((r for r in rows if r["DestinationCidrBlock"] == cidr), None)


def _wait_attachment_state(ec2, attachment_id: str, target: str, timeout_s: float) -> str:
    def probe():
        rows = ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attachment_id])[
            "TransitGatewayVpcAttachments"
        ]
        return rows[0]["State"] if rows else None

    return _poll(probe, lambda s: s == target, timeout_s=timeout_s)


def _retry_on_incorrect_state(fn: Callable[[], Any], timeout_s: float = 180.0, interval_s: float = 10.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "IncorrectState":
                raise
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _retry_on_tgw_limit(ec2, fn: Callable[[], Any], timeout_s: float = 1500.0, interval_s: float = 15.0) -> Any:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TransitGatewayLimitExceeded" or time.monotonic() >= deadline:
                raise
            _reclaim_stale_tgws(ec2)
            time.sleep(interval_s)


def _reclaim_stale_tgws(ec2, min_age_s: float = 1200.0) -> None:
    """Best-effort: free account TGW quota tied up by transit gateways THIS SAME
    self-contained check created and failed to tear down. Only ever deletes an
    "available" TGW carrying this check's Name-tag prefix, with no live attachment, AND
    old enough that it cannot be a sibling check's TGW still mid-flight."""
    try:
        tgws = ec2.describe_transit_gateways(Filters=[{"Name": "state", "Values": ["available"]}])[
            "TransitGateways"
        ]
    except ClientError:
        return
    now = datetime.now(timezone.utc)
    for tgw in tgws:
        name_tag = next((t["Value"] for t in tgw.get("Tags", []) if t["Key"] == "Name"), "")
        if not name_tag.startswith("sim2real-behav-tgwrtsb-"):
            continue
        creation_time = tgw.get("CreationTime")
        if creation_time is not None and (now - creation_time).total_seconds() < min_age_s:
            continue
        tgw_id = tgw["TransitGatewayId"]
        try:
            live = ec2.describe_transit_gateway_attachments(
                Filters=[
                    {"Name": "transit-gateway-id", "Values": [tgw_id]},
                    {
                        "Name": "state",
                        "Values": [
                            "available", "pending", "pendingAcceptance", "modifying",
                            "initiatingRequest", "rollingBack",
                        ],
                    },
                ]
            )["TransitGatewayAttachments"]
        except ClientError:
            continue
        if live:
            continue
        try:
            ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
        except ClientError:
            pass


def _create_tgw(ctx, ec2, name: str) -> str:
    created = _retry_on_tgw_limit(
        ec2,
        lambda: ec2.create_transit_gateway(
            Description=name,
            TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
        ),
    )
    tgw_id = created["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id)))
    _poll(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=180.0,
    )
    return tgw_id


def _create_vpc_and_subnet(ctx, ec2, name: str) -> tuple[str, str]:
    vpc = ec2.create_vpc(
        CidrBlock="10.220.0.0/24",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    vpc_id = vpc["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    _poll(
        lambda: ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]["State"],
        lambda s: s == "available",
        timeout_s=60.0,
    )
    subnet = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock="10.220.0.0/26",
        TagSpecifications=[{"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": name}]}],
    )
    subnet_id = subnet["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    return vpc_id, subnet_id


def _create_vpc_attachment(ctx, ec2, tgw_id: str, vpc_id: str, subnet_id: str, name: str) -> str:
    created = _retry_on_incorrect_state(
        lambda: ec2.create_transit_gateway_vpc_attachment(
            TransitGatewayId=tgw_id,
            VpcId=vpc_id,
            SubnetIds=[subnet_id],
            TagSpecifications=[
                {"ResourceType": "transit-gateway-attachment", "Tags": [{"Key": "Name", "Value": name}]}
            ],
        )
    )
    attachment_id = created["TransitGatewayVpcAttachment"]["TransitGatewayAttachmentId"]

    def _cleanup_attachment() -> None:
        _best_effort(lambda: ec2.delete_transit_gateway_vpc_attachment(TransitGatewayAttachmentId=attachment_id))
        _best_effort(
            lambda: _poll(
                lambda: _attachment_state_or(ec2, attachment_id, "missing"),
                lambda s: s in ("deleted", "missing"),
                timeout_s=420.0,
                interval_s=10.0,
            )
        )

    ctx.on_cleanup(_cleanup_attachment)
    return attachment_id


def _attachment_state_or(ec2, attachment_id: str, missing_value: str) -> str:
    rows = ec2.describe_transit_gateway_vpc_attachments(TransitGatewayAttachmentIds=[attachment_id])[
        "TransitGatewayVpcAttachments"
    ]
    return rows[0]["State"] if rows else missing_value


def _create_route_table(ctx, ec2, tgw_id: str, name: str) -> str:
    created = ec2.create_transit_gateway_route_table(
        TransitGatewayId=tgw_id,
        TagSpecifications=[
            {"ResourceType": "transit-gateway-route-table", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )
    rtb_id = created["TransitGatewayRouteTable"]["TransitGatewayRouteTableId"]

    def _cleanup_rtb() -> None:
        deadline = time.monotonic() + 180.0
        while True:
            try:
                ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=rtb_id)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "InvalidRouteTableID.NotFound":
                    return
                if code != "IncorrectState" or time.monotonic() >= deadline:
                    raise
                time.sleep(2.0)

    ctx.on_cleanup(_cleanup_rtb)
    _poll(
        lambda: ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[rtb_id])[
            "TransitGatewayRouteTables"
        ][0]["State"],
        lambda s: s == "available",
        timeout_s=60.0,
    )
    return rtb_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
