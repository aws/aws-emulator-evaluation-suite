"""reject-transit-gateway-peering-attachment-wrong-state-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reject-transit-gateway-peering-attachment-wrong-state-rejected"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RejectTransitGatewayPeeringAttachment on an accepted ("available") attachment fails with
    IncorrectState and its exact message and leaves it available, while rejecting a second
    pendingAcceptance attachment moves it to "rejected"."""
    ec2 = ctx.client("ec2")
    # Real AWS refuses AcceptTransitGatewayPeeringAttachment when the accept is issued from the
    # requester's own region endpoint, even against a same-account attachment: measured on real AWS,
    # an accept issued through the same client that created the attachment gets
    # InvalidParameterValue ("Cannot accept <id> as the source of the peering request") every time,
    # so the accepted/rejected boundary this check exists to test is unreachable without a client
    # that is genuinely pinned to the accepter's own region.
    peer_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    ec2_peer = ctx.client("ec2", region=peer_region)
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    tgw_requester = _create_tgw(ctx, ec2, "req")
    tgw_accepter = _create_tgw(ctx, ec2_peer, "acc")

    attachment_to_accept = _create_peering_attachment(
        ctx, ec2, ec2_peer, tgw_requester, tgw_accepter, account_id, peer_region
    )
    if attachment_to_accept is None:
        raise AssertionError(
            "CreateTransitGatewayPeeringAttachment to a peer in a genuinely different region "
            "was rejected outright in this account/partition -- the accepted/rejected "
            "wrong-state boundary is unreachable here"
        )

    pending_before_accept = _poll_until(
        lambda: _attachment_state(ec2_peer, attachment_to_accept),
        lambda s: s in ("pendingAcceptance", "failed"),
        timeout_s=180.0,
    )
    assert pending_before_accept == "pendingAcceptance", (
        f"attachment never reached pendingAcceptance before accepting: {pending_before_accept}"
    )

    try:
        ec2_peer.accept_transit_gateway_peering_attachment(TransitGatewayAttachmentId=attachment_to_accept)
    except ClientError as exc:
        raise AssertionError(f"ACCEPT_ERR={exc.response['Error']['Code']}:{exc.response['Error']['Message']}") from None
    available = _poll_until(
        lambda: _attachment_state(ec2_peer, attachment_to_accept),
        lambda s: s in ("available", "failed"),
        timeout_s=240.0,
    )
    assert available == "available", f"peering attachment never became available: {available}"
    # --- Negative: rejecting an already-accepted (available) attachment is a wrong-state error ---
    code, message = _error(
        lambda: ec2_peer.reject_transit_gateway_peering_attachment(
            TransitGatewayAttachmentId=attachment_to_accept
        )
    )
    expected = f"{attachment_to_accept} is in invalid state"
    assert (code, message) == ("IncorrectState", expected), (
        f"expected IncorrectState {expected!r}, got {code!r} {message!r}"
    )

    # Effect absent: the attachment's state is still available, not rejected.
    still_available = _attachment_state(ec2_peer, attachment_to_accept)
    assert still_available == "available", (
        f"rejected RejectTransitGatewayPeeringAttachment call still changed the state: {still_available}"
    )

    # --- Positive control: a second, still-pendingAcceptance attachment rejects cleanly ---
    # A fresh accepter TGW, not the one already paired with tgw_requester above: the first
    # attachment is now durably "available" (not deleted), and a second concurrent attachment
    # between the identical TGW pair is not a state this check needs to also characterize.
    tgw_accepter2 = _create_tgw(ctx, ec2_peer, "acc2")
    attachment_to_reject = _create_peering_attachment(
        ctx, ec2, ec2_peer, tgw_requester, tgw_accepter2, account_id, peer_region
    )
    assert attachment_to_reject is not None, (
        "CreateTransitGatewayPeeringAttachment to a second, freshly created peer TGW was "
        "rejected outright, even though the first, identical-shaped call above succeeded"
    )
    pending = _poll_until(
        lambda: _attachment_state(ec2_peer, attachment_to_reject),
        lambda s: s in ("pendingAcceptance", "failed"),
        timeout_s=180.0,
    )
    assert pending == "pendingAcceptance", f"second attachment never reached pendingAcceptance: {pending}"

    ec2_peer.reject_transit_gateway_peering_attachment(TransitGatewayAttachmentId=attachment_to_reject)
    rejected = _poll_until(
        lambda: _attachment_state(ec2_peer, attachment_to_reject),
        lambda s: s == "rejected",
        timeout_s=120.0,
    )
    assert rejected == "rejected", f"attachment never reached rejected state: {rejected}"


def _create_tgw(ctx, ec2, tag: str) -> str:
    tgw_id = ec2.create_transit_gateway(
        Description=ctx.unique_name(f"sim2real-tgwpeer-{tag}-"),
        TagSpecifications=[
            {
                "ResourceType": "transit-gateway",
                "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-tgwpeer-{tag}-")}],
            }
        ],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _safe(lambda: ec2.delete_transit_gateway(TransitGatewayId=tgw_id)))
    _poll_until(
        lambda: ec2.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0]["State"],
        lambda s: s == "available",
        timeout_s=180.0,
    )
    return tgw_id


def _create_peering_attachment(
    ctx, ec2, ec2_peer, requester_tgw: str, accepter_tgw: str, account_id: str, peer_region: str
):
    attachment_id = None
    try:
        resp = ec2.create_transit_gateway_peering_attachment(
            TransitGatewayId=requester_tgw,
            PeerTransitGatewayId=accepter_tgw,
            PeerAccountId=account_id,
            PeerRegion=peer_region,
        )
        attachment_id = resp["TransitGatewayPeeringAttachment"]["TransitGatewayAttachmentId"]
    except ClientError as exc:
        exc.response["Error"]["Code"]

    if attachment_id is None:
        return None

    # Delete via the accepter's own region endpoint: measured on real AWS, the accept/reject
    # boundary this check exercises only answers from that side (see the peer_region comment in
    # run()), so cleanup uses the same side.
    ctx.on_cleanup(
        lambda: _safe(
            lambda: ec2_peer.delete_transit_gateway_peering_attachment(TransitGatewayAttachmentId=attachment_id)
        )
    )
    return attachment_id


def _attachment_state(ec2, attachment_id: str):
    # A peering attachment created via the requester's region takes a real, measured moment to
    # propagate into the accepter's own region -- describing it there before that propagation
    # completes answers InvalidTransitGatewayAttachmentID.NotFound rather than an empty list.
    # Treat that exactly like "not visible yet", the same as an empty result, so the caller's poll
    # can keep waiting instead of crashing on a transient cross-region lag.
    try:
        resp = ec2.describe_transit_gateway_peering_attachments(TransitGatewayAttachmentIds=[attachment_id])
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidTransitGatewayAttachmentID.NotFound":
            return None
        raise
    attachments = resp["TransitGatewayPeeringAttachments"]
    if not attachments:
        return None
    return attachments[0]["State"]


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 5.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last observed value: {value!r}")


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. A success raises: an
    accepted call is the strongest signal and must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "InvalidTransitGatewayAttachmentID.NotFound",
            "InvalidTransitGatewayID.NotFound",
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
