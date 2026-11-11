"""transit-gateway-route-table-announcement-over-pending-peering-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transit-gateway-route-table-announcement-over-pending-peering-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A same-account TGW peering attachment stays pendingAcceptance: the requester's own accept fails with
    InvalidParameterValue, and CreateTransitGatewayRouteTableAnnouncement over it fails with
    IncorrectState (exact messages), leaving the attachment pending and no announcement behind."""
    ec2 = ctx.client("ec2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    tgw1_id = _create_tgw(ctx, ec2)
    tgw2_id = _create_tgw(ctx, ec2)

    name = ctx.unique_name("sim2real-tgwrta-")
    peer = ec2.create_transit_gateway_peering_attachment(
        TransitGatewayId=tgw1_id,
        PeerTransitGatewayId=tgw2_id,
        PeerAccountId=account_id,
        PeerRegion=ctx.region,
        TagSpecifications=[
            {"ResourceType": "transit-gateway-attachment", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["TransitGatewayPeeringAttachment"]
    attach_id = peer["TransitGatewayAttachmentId"]

    def _teardown_attachment():
        _safe(
            lambda: ec2.delete_transit_gateway_peering_attachment(
                TransitGatewayAttachmentId=attach_id
            )
        )
        # A transit gateway cannot be deleted while an attachment still
        # references it, even one that is mid-deletion -- wait for it to
        # fully clear before the TGW cleanups (registered before this one,
        # so they run after it) fire.
        # A fully deleted attachment stops resolving (NotFound), which _safe accepts as gone.
        _safe(lambda: _poll_until(
            lambda: ec2.describe_transit_gateway_peering_attachments(
                TransitGatewayAttachmentIds=[attach_id]
            )["TransitGatewayPeeringAttachments"],
            lambda lst: lst == [] or lst[0]["State"] == "deleted",
            timeout_s=_teardown_left(ec2),
            interval_s=2,
        ))

    ctx.on_cleanup(_teardown_attachment)

    # --- positive control: the account/creds/region are healthy for this API, and the
    # peering request itself is accepted and reaches the only state a same-account
    # attachment can reach. ---
    peer = _poll_until(
        lambda: ec2.describe_transit_gateway_peering_attachments(
            TransitGatewayAttachmentIds=[attach_id]
        )["TransitGatewayPeeringAttachments"][0],
        lambda a: a["State"] == "pendingAcceptance",
        timeout_s=180,
    )
    assert peer["State"] == "pendingAcceptance", (
        f"expected the same-account attachment to land in pendingAcceptance, got {peer['State']!r}"
    )

    # --- refusal #1: the requester (the caller) can never also be the accepter. ---
    try:
        ec2.accept_transit_gateway_peering_attachment(TransitGatewayAttachmentId=attach_id)
        raise AssertionError("self-accept of a same-account peering attachment unexpectedly succeeded")
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "InvalidParameterValue", f"unexpected code rejecting self-accept: {code}"
        message = err.response["Error"].get("Message")
        expected = f"Cannot accept {attach_id} as the source of the peering request."
        assert message == expected, f"unexpected message rejecting self-accept: {message!r}"

    unchanged = ec2.describe_transit_gateway_peering_attachments(
        TransitGatewayAttachmentIds=[attach_id]
    )["TransitGatewayPeeringAttachments"][0]
    assert unchanged["State"] == "pendingAcceptance", (
        f"a rejected self-accept must not mutate the attachment's state, got {unchanged['State']!r}"
    )

    rt = ec2.create_transit_gateway_route_table(
        TransitGatewayId=tgw1_id,
        TagSpecifications=[
            {"ResourceType": "transit-gateway-route-table", "Tags": [{"Key": "Name", "Value": name}]}
        ],
    )["TransitGatewayRouteTable"]
    rt_id = rt["TransitGatewayRouteTableId"]

    def _teardown_route_table():
        _safe(
            lambda: ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=rt_id)
        )
        # A fully deleted route table answers InvalidRouteTableID.NotFound, which _safe accepts.
        _safe(lambda: _poll_until(
            lambda: ec2.describe_transit_gateway_route_tables(
                TransitGatewayRouteTableIds=[rt_id]
            )["TransitGatewayRouteTables"],
            lambda lst: lst == [] or lst[0]["State"] == "deleted",
            timeout_s=_teardown_left(ec2),
            interval_s=2,
        ))

    ctx.on_cleanup(_teardown_route_table)
    _poll_until(
        lambda: ec2.describe_transit_gateway_route_tables(
            TransitGatewayRouteTableIds=[rt_id]
        )["TransitGatewayRouteTables"][0],
        lambda r: r["State"] == "available",
        timeout_s=120,
    )

    # --- refusal #2: creating an announcement over a peering attachment that is
    # permanently stuck in pendingAcceptance is rejected, and no announcement is left
    # behind. ---
    try:
        ec2.create_transit_gateway_route_table_announcement(
            TransitGatewayRouteTableId=rt_id, PeeringAttachmentId=attach_id
        )
        raise AssertionError(
            "creating an announcement over a pendingAcceptance peering attachment unexpectedly succeeded"
        )
    except ClientError as err:
        code = err.response["Error"]["Code"]
        assert code == "IncorrectState", f"unexpected code rejecting the announcement create: {code}"
        message = err.response["Error"].get("Message")
        expected = f"{attach_id} is in invalid state"
        assert message == expected, f"unexpected message rejecting the announcement create: {message!r}"

    after = ec2.describe_transit_gateway_route_table_announcements(
        Filters=[{"Name": "transit-gateway-route-table-id", "Values": [rt_id]}]
    )["TransitGatewayRouteTableAnnouncements"]
    assert after == [], f"a rejected create must not leave an announcement behind, got {after!r}"


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidRouteTableID.NotFound",
            "InvalidTransitGatewayAttachmentID.NotFound",
            "InvalidTransitGatewayID.NotFound",
        ):
            raise


# budget.cleanup_timeout for behavioral/ec2: one deadline shared by the check's teardowns.
_TEARDOWN_RETRY_S = 900.0
_TEARDOWN_DEADLINES: dict = {}


def _teardown_left(ec2) -> float:
    held = _TEARDOWN_DEADLINES.get(id(ec2))
    if held is None or held[0] is not ec2:
        held = _TEARDOWN_DEADLINES[id(ec2)] = (ec2, time.monotonic() + _TEARDOWN_RETRY_S)
    return max(1.0, held[1] - time.monotonic())


def _delete_tgw(ec2, tgw_id):
    """Delete the TGW; retry IncorrectState while an attachment is still deleting, and throttling,
    every 2 s to the shared cleanup deadline. A gone TGW is done."""
    _teardown_left(ec2)
    deadline = _TEARDOWN_DEADLINES[id(ec2)][1]
    while True:
        try:
            ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidTransitGatewayID.NotFound":
                return
            if code not in ("IncorrectState", "RequestLimitExceeded") or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _create_tgw(ctx, ec2) -> str:
    name = ctx.unique_name("sim2real-tgw-")
    tgw_id = ec2.create_transit_gateway(
        Description=name,
        TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _delete_tgw(ec2, tgw_id))
    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])[
            "TransitGateways"
        ][0],
        lambda t: t["State"] == "available",
        timeout_s=240,
    )
    return tgw_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
