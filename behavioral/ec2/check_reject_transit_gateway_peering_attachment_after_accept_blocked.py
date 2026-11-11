"""reject-transit-gateway-peering-attachment-after-accept-blocked."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "reject-transit-gateway-peering-attachment-after-accept-blocked"
GROUP = "overly-permissive"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RejectTransitGatewayPeeringAttachment on an attachment already 'available' via Accept is
    refused with IncorrectState and leaves it 'available'; a still-pendingAcceptance attachment
    can still be rejected."""
    ec2 = ctx.client("ec2")
    # AWS refuses AcceptTransitGatewayPeeringAttachment from the requester's side, even for a
    # same-account, same-region attachment (InvalidParameterValue "Cannot accept <id> as the
    # source of the peering request"). The accepter TGWs therefore live in a second region, and
    # every accept/reject/describe of the attachment goes through that region's client.
    peer_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    ec2_peer = ctx.client("ec2", region=peer_region)
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-tgwreject-")

    tgw_a = _create_tgw(ctx, ec2, name + "-a")
    tgw_b = _create_tgw(ctx, ec2_peer, name + "-b")

    # ---- Negative: create a same-account, cross-region peering attachment, accept it, then
    # attempt to reject the now-available attachment ----
    attach_id = _create_peering(ctx, ec2, ec2_peer, tgw_a, tgw_b, account_id, peer_region)
    _poll_until(lambda: _state(ec2_peer, attach_id), lambda s: s == "pendingAcceptance", timeout_s=240, interval_s=5)

    ec2_peer.accept_transit_gateway_peering_attachment(TransitGatewayAttachmentId=attach_id)
    _poll_until(lambda: _state(ec2_peer, attach_id), lambda s: s == "available", timeout_s=300, interval_s=5)

    code, message = _error(
        lambda: ec2_peer.reject_transit_gateway_peering_attachment(TransitGatewayAttachmentId=attach_id)
    )
    expected = f"{attach_id} is in invalid state"
    assert (code, message) == ("IncorrectState", expected), (
        f"expected IncorrectState {expected!r}, got {code!r} {message!r}"
    )

    # Effect absence: the accepted attachment is unaffected, still 'available'.
    assert _state(ec2_peer, attach_id) == "available"

    # ---- Positive control: a fresh, still-pendingAcceptance attachment CAN be rejected ----
    tgw_c = _create_tgw(ctx, ec2_peer, name + "-c")
    attach2_id = _create_peering(ctx, ec2, ec2_peer, tgw_a, tgw_c, account_id, peer_region)
    _poll_until(lambda: _state(ec2_peer, attach2_id), lambda s: s == "pendingAcceptance", timeout_s=240, interval_s=5)
    ec2_peer.reject_transit_gateway_peering_attachment(TransitGatewayAttachmentId=attach2_id)
    rejected_state = _poll_until(
        lambda: _state(ec2_peer, attach2_id), lambda s: s == "rejected", timeout_s=180, interval_s=5
    )
    assert rejected_state == "rejected"


# ===== helpers =====

def _create_tgw(ctx, client, name: str) -> str:
    from botocore.exceptions import ClientError

    # Transit gateways are a low, account-wide quota (default 5/region) shared with every other
    # check running concurrently in this account, so a transient TransitGatewayLimitExceeded is
    # expected under load and worth a short bounded retry rather than an outright failure.
    deadline = time.monotonic() + 45.0
    while True:
        try:
            tgw_id = client.create_transit_gateway(
                Description=name,
                TagSpecifications=[
                    {
                        "ResourceType": "transit-gateway",
                        "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
                    }
                ],
            )["TransitGateway"]["TransitGatewayId"]
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransitGatewayLimitExceeded" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise
    ctx.on_cleanup(lambda: _delete_tgw(client, tgw_id))

    def _tgw_state():
        return client.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"]

    _poll_until(_tgw_state, lambda s: s == "available", timeout_s=300, interval_s=5)
    return tgw_id


def _create_peering(ctx, ec2, ec2_peer, tgw_id: str, peer_tgw_id: str, account_id: str, peer_region: str) -> str:
    attach_id = ec2.create_transit_gateway_peering_attachment(
        TransitGatewayId=tgw_id,
        PeerTransitGatewayId=peer_tgw_id,
        PeerAccountId=account_id,
        PeerRegion=peer_region,
    )["TransitGatewayPeeringAttachment"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(lambda: _delete_peering(ec2, attach_id))
    return attach_id


def _state(ec2, attach_id: str):
    # The attachment takes a moment to propagate to the accepter's region; until then the
    # describe there answers InvalidTransitGatewayAttachmentID.NotFound, read as "not visible yet".
    from botocore.exceptions import ClientError

    try:
        atts = ec2.describe_transit_gateway_peering_attachments(TransitGatewayAttachmentIds=[attach_id])[
            "TransitGatewayPeeringAttachments"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidTransitGatewayAttachmentID.NotFound":
            return None
        raise
    return atts[0]["State"] if atts else None


def _delete_peering(ec2, attach_id: str) -> None:
    """Delete the attachment from the requester side and wait until it is gone, so the TGW
    deletes that follow are not refused for a still-attached peering."""
    # A rejected attachment is refused with IncorrectState; AWS removes it without a delete.
    if _state(ec2, attach_id) not in (None, "deleted", "deleting", "rejected", "rejecting", "failed", "failing"):
        _ignore_error(lambda: ec2.delete_transit_gateway_peering_attachment(TransitGatewayAttachmentId=attach_id))
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline and _state(ec2, attach_id) not in (None, "deleted", "rejected", "failed"):
        time.sleep(10)


def _delete_tgw(client, tgw_id: str) -> None:
    """Delete the TGW, retrying while an attachment is still being torn down."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 300.0
    while True:
        try:
            client.delete_transit_gateway(TransitGatewayId=tgw_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidTransitGatewayID.NotFound":
                return
            if code in ("IncorrectState", "DependencyViolation") and time.monotonic() < deadline:
                time.sleep(15)
                continue
            raise


def _error(fn: Callable[[], Any]):
    """Call fn(); return the (code, message) of its ClientError. A success raises: an
    accepted call is the strongest signal and must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ignore_error(fn: Callable[[], Any]) -> None:
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayAttachmentID.NotFound":
            raise


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
