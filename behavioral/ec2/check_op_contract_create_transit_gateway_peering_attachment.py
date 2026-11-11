"""op-contract-create-transit-gateway-peering-attachment."""
from __future__ import annotations

import time
from typing import Any, Callable, Optional

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-create-transit-gateway-peering-attachment"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTransitGatewayPeeringAttachment to a nonexistent peer gateway fails with
    InvalidTransitGatewayID.NotFound; a valid request reaches pendingAcceptance, and the requester's
    own accept fails with InvalidParameterValue (exact messages) and leaves that state unchanged."""
    ec2 = ctx.client("ec2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    tgw1 = _create_tgw(ctx, "req")
    tgw2 = _create_tgw(ctx, "acc")
    _wait_tgw_available(ctx, tgw1)
    _wait_tgw_available(ctx, tgw2)

    # --- error boundary: peer transit gateway that doesn't exist ---
    code, message = _error_of(
        lambda: ec2.create_transit_gateway_peering_attachment(
            TransitGatewayId=tgw1,
            PeerTransitGatewayId="tgw-00000000000000000",
            PeerAccountId=account_id,
            PeerRegion=ctx.region,
        )
    )
    assert code == "InvalidTransitGatewayID.NotFound", f"unexpected code: {code}"
    assert message == "Transit Gateway tgw-00000000000000000 was deleted or does not exist.", message

    # --- success path ---
    resp = ec2.create_transit_gateway_peering_attachment(
        TransitGatewayId=tgw1,
        PeerTransitGatewayId=tgw2,
        PeerAccountId=account_id,
        PeerRegion=ctx.region,
    )
    att = resp["TransitGatewayPeeringAttachment"]
    attach_id = att["TransitGatewayAttachmentId"]
    ctx.on_cleanup(lambda: _cleanup_peering(ctx, attach_id))
    assert att["RequesterTgwInfo"]["TransitGatewayId"] == tgw1
    assert att["AccepterTgwInfo"]["TransitGatewayId"] == tgw2
    assert att["State"] in ("initiating", "initiatingRequest", "pendingAcceptance"), att["State"]

    def _state() -> str:
        d = ec2.describe_transit_gateway_peering_attachments(TransitGatewayAttachmentIds=[attach_id])
        return d["TransitGatewayPeeringAttachments"][0]["State"]

    _poll_until(lambda: _state(), lambda s: s == "pendingAcceptance", timeout_s=120.0)

    # The requester cannot accept its own peering request: AcceptTransitGatewayPeeringAttachment
    # fails with InvalidParameterValue and the attachment stays in pendingAcceptance.
    accept_code, accept_message = _error_of(
        lambda: ec2.accept_transit_gateway_peering_attachment(TransitGatewayAttachmentId=attach_id)
    )
    assert accept_code == "InvalidParameterValue", f"unexpected code: {accept_code}"
    assert accept_message == f"Cannot accept {attach_id} as the source of the peering request.", (
        accept_message
    )
    assert _state() == "pendingAcceptance", "a rejected self-accept must not mutate the attachment's state"


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

    # The default transit gateway quota is small and can be held by stale or concurrent
    # "sim2real" gateways: reclaim stale ones and retry within a bounded window.
    deadline = time.monotonic() + 600.0
    last_err: Optional[Exception] = None
    resp = None
    while time.monotonic() < deadline:
        try:
            resp = _do_create()
            break
        except ClientError as err:
            if err.response["Error"]["Code"] != "TransitGatewayLimitExceeded":
                raise
            last_err = err
            _reclaim_stale_tgws(ec2)
            time.sleep(2)
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

    def _state() -> str:
        d = ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])
        return d["TransitGateways"][0]["State"]

    _poll_until(lambda: _state(), lambda s: s == "available", timeout_s=180.0)


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
