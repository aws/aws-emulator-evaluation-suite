"""op-contract-create-transit-gateway-route-table-announcement."""
from __future__ import annotations

import time
from typing import Any, Callable, Optional

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-transit-gateway-route-table-announcement"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTransitGatewayRouteTableAnnouncement on a peering attachment in pendingAcceptance answers
    DryRun with DryRunOperation and the real call with IncorrectState (exact messages), and neither
    call creates an announcement."""
    ec2 = ctx.client("ec2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    tgw1 = _create_tgw(ctx, "req")
    tgw2 = _create_tgw(ctx, "acc")
    _wait_tgw_available(ctx, tgw1)
    _wait_tgw_available(ctx, tgw2)
    rt_id = _create_route_table(ctx, tgw1)
    attach_id = _create_peering_pending_acceptance(ctx, tgw1, tgw2, account_id)

    # --- error boundary: DryRun must fail with DryRunOperation and create nothing ---
    code, message = _error_of(
        lambda: ec2.create_transit_gateway_route_table_announcement(
            PeeringAttachmentId=attach_id, TransitGatewayRouteTableId=rt_id, DryRun=True
        )
    )
    assert code == "DryRunOperation", f"unexpected code: {code}"
    assert message == "Request would have succeeded, but DryRun flag is set.", message
    before = ec2.describe_transit_gateway_route_table_announcements(
        Filters=[{"Name": "transit-gateway-route-table-id", "Values": [rt_id]}]
    )["TransitGatewayRouteTableAnnouncements"]
    assert before == [], "DryRun must not create an announcement"

    # The real call also requires a usable peering attachment; one in pendingAcceptance makes it fail
    # with IncorrectState instead of creating an announcement.
    code, message = _error_of(
        lambda: ec2.create_transit_gateway_route_table_announcement(
            PeeringAttachmentId=attach_id, TransitGatewayRouteTableId=rt_id
        )
    )
    assert code == "IncorrectState", f"unexpected code: {code}"
    assert message == f"{attach_id} is in invalid state", message
    after = ec2.describe_transit_gateway_route_table_announcements(
        Filters=[{"Name": "transit-gateway-route-table-id", "Values": [rt_id]}]
    )["TransitGatewayRouteTableAnnouncements"]
    assert after == [], "a rejected create must not create an announcement"


def _error_of(fn: Callable[[], Any]) -> tuple[str, str]:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"]["Message"]
    raise AssertionError("the call real AWS rejects was accepted")


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float = 120.0, interval_s: float = 4.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _create_tgw(ctx, suffix: str) -> str:
    from botocore.exceptions import ClientError

    ec2 = ctx.client("ec2")
    name = ctx.unique_name(f"sim2real-behav-tgw-{suffix}-")

    def _do_create():
        return ec2.create_transit_gateway(
            Description=name,
            TagSpecifications=[{"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": name}]}],
        )

    try:
        resp = _do_create()
    except ClientError as err:
        if err.response["Error"]["Code"] != "TransitGatewayLimitExceeded":
            raise
        # The default transit gateway quota is small and can be held by stale or concurrent
        # "sim2real" gateways: reclaim stale ones and retry within a bounded window.
        deadline = time.monotonic() + 600.0
        last_err: Optional[Exception] = err
        resp = None
        while time.monotonic() < deadline:
            _reclaim_stale_tgws(ec2)
            time.sleep(2)
            try:
                resp = _do_create()
                break
            except ClientError as err2:
                if err2.response["Error"]["Code"] != "TransitGatewayLimitExceeded":
                    raise
                last_err = err2
        if resp is None:
            raise last_err

    tgw_id = resp["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _delete_tgw(ctx, tgw_id))
    return tgw_id


def _reclaim_stale_tgws(ec2) -> None:
    from datetime import datetime, timezone

    cutoff = datetime.now(timezone.utc).timestamp() - 900  # 15 minutes
    resp = ec2.describe_transit_gateways(
        Filters=[{"Name": "state", "Values": ["available", "pending", "modifying"]}]
    )
    for tgw in resp["TransitGateways"]:
        tag_map = {t["Key"]: t["Value"] for t in tgw.get("Tags", [])}
        created = tgw.get("CreationTime")
        if (
            tag_map.get("Name", "").startswith("sim2real-behav-tgw-")
            and created is not None
            and created.timestamp() < cutoff
        ):
            try:
                ec2.delete_transit_gateway(TransitGatewayId=tgw["TransitGatewayId"])
            except Exception:
                pass


def _wait_tgw_available(ctx, tgw_id: str) -> None:
    ec2 = ctx.client("ec2")
    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=180.0,
    )


def _create_route_table(ctx, tgw_id: str) -> str:
    ec2 = ctx.client("ec2")
    rt_id = ec2.create_transit_gateway_route_table(TransitGatewayId=tgw_id)["TransitGatewayRouteTable"][
        "TransitGatewayRouteTableId"
    ]
    ctx.on_cleanup(lambda: _delete_route_table(ctx, rt_id))
    _poll_until(
        lambda: ec2.describe_transit_gateway_route_tables(TransitGatewayRouteTableIds=[rt_id])[
            "TransitGatewayRouteTables"
        ][0]["State"],
        lambda s: s in ("available", "failed"),
        timeout_s=90.0,
    )
    return rt_id


def _create_peering_pending_acceptance(ctx, tgw1: str, tgw2: str, account_id: str) -> str:
    ec2 = ctx.client("ec2")
    attach_id = ec2.create_transit_gateway_peering_attachment(
        TransitGatewayId=tgw1, PeerTransitGatewayId=tgw2, PeerAccountId=account_id, PeerRegion=ctx.region
    )["TransitGatewayPeeringAttachment"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(lambda: _cleanup_peering(ctx, attach_id))

    def _state() -> str:
        d = ec2.describe_transit_gateway_peering_attachments(TransitGatewayAttachmentIds=[attach_id])
        return d["TransitGatewayPeeringAttachments"][0]["State"]

    _poll_until(lambda: _state(), lambda s: s == "pendingAcceptance", timeout_s=120.0)

    # The requester cannot accept its own peering request; assert the rejection, after which the
    # attachment stays in pendingAcceptance.
    from botocore.exceptions import ClientError

    try:
        ec2.accept_transit_gateway_peering_attachment(TransitGatewayAttachmentId=attach_id)
        raise AssertionError("self-accept unexpectedly succeeded")
    except ClientError as err:
        assert err.response["Error"]["Code"] == "InvalidParameterValue", err.response["Error"]["Code"]
        assert err.response["Error"]["Message"] == (
            f"Cannot accept {attach_id} as the source of the peering request."
        ), err.response["Error"]["Message"]
    assert _state() == "pendingAcceptance", "a rejected self-accept must not mutate the attachment's state"
    return attach_id


def _delete_announcement(ctx, ann_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_transit_gateway_route_table_announcement(TransitGatewayRouteTableAnnouncementId=ann_id)
    except Exception:
        pass


def _cleanup_peering(ctx, attach_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_transit_gateway_peering_attachment(TransitGatewayAttachmentId=attach_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayAttachmentID.NotFound":
            raise
        return
    try:
        _poll_until(
            lambda: ec2.describe_transit_gateway_peering_attachments(TransitGatewayAttachmentIds=[attach_id])[
                "TransitGatewayPeeringAttachments"
            ][0]["State"],
            lambda s: s in ("deleted", "failed"),
            timeout_s=180.0,
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayAttachmentID.NotFound":
            raise


def _delete_route_table(ctx, rt_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_transit_gateway_route_table(TransitGatewayRouteTableId=rt_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidRouteTableID.NotFound":
            raise


def _delete_tgw(ctx, tgw_id: str) -> None:
    ec2 = ctx.client("ec2")
    try:
        ec2.delete_transit_gateway(TransitGatewayId=tgw_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayID.NotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
