"""transit-gateway-route-table-association-moves-between-tables."""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transit-gateway-route-table-association-moves-between-tables"
GROUP = "transit-gateway"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A VPC attachment auto-associates with its transit gateway's default route table;
    moving it to another table takes a disassociate-then-associate pair, and a second
    associate attempted while it is still on the default table is rejected."""
    ec2 = ctx.client("ec2")
    name = ctx.unique_name("sim2real-behav-tgwmv-")

    vpc_id, subnet_id = _create_vpc_and_subnet(ctx, ec2, name)
    tgw_id = _create_tgw(ctx, ec2, name)
    attachment_id = _create_vpc_attachment(ctx, ec2, tgw_id, vpc_id, subnet_id, name)
    _wait_attachment_state(ec2, attachment_id, "available", timeout_s=240.0)

    default_rtb_id = _poll(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]
        .get("Options", {})
        .get("AssociationDefaultRouteTableId"),
        lambda v: v is not None,
        timeout_s=60.0,
    )
    assert default_rtb_id, "transit gateway has no AssociationDefaultRouteTableId"

    # Side effect of CreateTransitGatewayVpcAttachment: the attachment lands on the
    # gateway's own default route table without any explicit Associate call.
    default_state = _poll(
        lambda: _association_state(ec2, default_rtb_id, attachment_id),
        lambda s: s == "associated",
        timeout_s=180.0,
    )
    assert default_state == "associated", (
        f"expected the new attachment to auto-associate with the default route table "
        f"{default_rtb_id!r}, last observed state {default_state!r}"
    )

    other_rtb_id = _create_route_table(ctx, ec2, tgw_id, name)
    # A new route table starts pending and becomes available on its own.
    described = _poll(
        lambda: ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[other_rtb_id])[
            "TransitGatewayRouteTables"
        ][0],
        lambda t: t["State"] != "pending",
        timeout_s=180.0,
    )
    assert described["State"] == "available", f"expected available, got {described['State']!r}"
    assert described["DefaultAssociationRouteTable"] is False, (
        f"expected a freshly created non-default route table, got "
        f"DefaultAssociationRouteTable={described['DefaultAssociationRouteTable']!r}"
    )

    # Still associated with the default table, so a second associate is refused.
    code, message = _error_code(
        lambda: ec2.associate_transit_gateway_route_table(
            TransitGatewayRouteTableId=other_rtb_id, TransitGatewayAttachmentId=attachment_id
        )
    )
    assert code == "Resource.AlreadyAssociated", f"expected Resource.AlreadyAssociated, got {code!r}"
    expected = f"Transit Gateway Attachment {attachment_id} is already associated to a route table."
    assert message == expected, f"unexpected message: {message!r}"

    disassoc = ec2.disassociate_transit_gateway_route_table(
        TransitGatewayRouteTableId=default_rtb_id, TransitGatewayAttachmentId=attachment_id
    )
    assert disassoc["Association"]["State"] in ("disassociating", "disassociated"), (
        f"expected disassociating/disassociated, got {disassoc['Association']['State']!r}"
    )
    _poll(
        lambda: _association_state(ec2, default_rtb_id, attachment_id, treat_gone_as="gone"),
        lambda s: s == "gone",
        timeout_s=180.0,
    )

    assoc = ec2.associate_transit_gateway_route_table(
        TransitGatewayRouteTableId=other_rtb_id, TransitGatewayAttachmentId=attachment_id
    )
    assert assoc["Association"]["State"] in ("associating", "associated"), (
        f"expected associating/associated, got {assoc['Association']['State']!r}"
    )

    final_state = _poll(
        lambda: _association_state(ec2, other_rtb_id, attachment_id),
        lambda s: s == "associated",
        timeout_s=180.0,
    )
    assert final_state == "associated", f"association on the new table never settled (last={final_state!r})"

    rows = ec2.get_transit_gateway_route_table_associations(TransitGatewayRouteTableId=other_rtb_id)[
        "Associations"
    ]
    found = next((r for r in rows if r["TransitGatewayAttachmentId"] == attachment_id), None)
    assert found is not None, f"expected attachment {attachment_id!r} among associations, got {rows}"
    assert found["ResourceType"] == "vpc", f"expected ResourceType vpc, got {found['ResourceType']!r}"

    # Independent read: the default table no longer carries the attachment.
    rows_default = ec2.get_transit_gateway_route_table_associations(TransitGatewayRouteTableId=default_rtb_id)[
        "Associations"
    ]
    assert not any(r["TransitGatewayAttachmentId"] == attachment_id for r in rows_default), (
        f"attachment {attachment_id!r} should have moved off the default table, got {rows_default}"
    )


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


def _error_code(fn: Callable[[], Any]) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


def _best_effort(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidRouteTableID.NotFound",
            "InvalidSubnetID.NotFound",
            "InvalidTransitGatewayAttachmentID.NotFound",
            "InvalidTransitGatewayID.NotFound",
            "InvalidVpcID.NotFound",
        ):
            raise


def _association_state(ec2, route_table_id: str, attachment_id: str, treat_gone_as: str | None = None) -> str:
    rows = ec2.get_transit_gateway_route_table_associations(
        TransitGatewayRouteTableId=route_table_id,
        Filters=[{"Name": "transit-gateway-attachment-id", "Values": [attachment_id]}],
    )["Associations"]
    if not rows:
        return treat_gone_as
    return rows[0]["State"]


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
        if not name_tag.startswith("sim2real-behav-tgwmv-"):
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
        CidrBlock="10.217.0.0/24",
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
        CidrBlock="10.217.0.0/26",
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
        # LIFO runs this before the attachment's own cleanup, so a route table that
        # still carries that attachment's association must disassociate it here rather
        # than wait on cleanup ordering it does not control.
        deadline = time.monotonic() + 300.0
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
                try:
                    live = ec2.get_transit_gateway_route_table_associations(
                        TransitGatewayRouteTableId=rtb_id
                    )["Associations"]
                except ClientError as inner:
                    if inner.response["Error"]["Code"] != "InvalidRouteTableID.NotFound":
                        raise
                    return
                for assoc in live:
                    _best_effort(
                        lambda a=assoc: ec2.disassociate_transit_gateway_route_table(
                            TransitGatewayRouteTableId=rtb_id,
                            TransitGatewayAttachmentId=a["TransitGatewayAttachmentId"],
                        )
                    )
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
