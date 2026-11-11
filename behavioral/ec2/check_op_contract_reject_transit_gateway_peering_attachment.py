"""op-contract-reject-transit-gateway-peering-attachment."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-reject-transit-gateway-peering-attachment"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RejectTransitGatewayPeeringAttachment with DryRun fails with DryRunOperation and its exact message;
    without DryRun it moves a same-account pendingAcceptance peering attachment to "rejecting" and then
    "rejected"."""
    ec2 = ctx.client("ec2")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    # The check creates its own pair of transit gateways: deleting a TGW cascades to every
    # attachment on it, so a reused TGW another check deletes would take the pending peering
    # attachment with it. TransitGatewayLimitExceeded (default 5/region) is retried as contention,
    # within a budget that leaves the later steps room inside the check's own time limit.
    # Reject is the accepter's call, and AWS refuses it from the requester's side, so the accepter
    # TGW lives in a second region and every accepter-side call goes through that region's client.
    peer_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    ec2_peer = ctx.client("ec2", region=peer_region)
    tgw_create_deadline = time.monotonic() + 300.0
    name_a = ctx.unique_name("sim2real-peer-a-")
    tgw_a = _create_tgw_with_retry(ec2, description=name_a, deadline=tgw_create_deadline, interval_s=15)
    teardown_deadline: dict = {}
    ctx.on_cleanup(lambda: _delete_tgw(ec2, tgw_a, teardown_deadline))
    name_b = ctx.unique_name("sim2real-peer-b-")
    tgw_b = _create_tgw_with_retry(ec2_peer, description=name_b, deadline=tgw_create_deadline, interval_s=15)
    ctx.on_cleanup(lambda: _delete_tgw(ec2_peer, tgw_b, teardown_deadline))

    for client, tgw_id in ((ec2, tgw_a), (ec2_peer, tgw_b)):
        _poll_until(
            lambda c=client, tid=tgw_id: c.describe_transit_gateways(TransitGatewayIds=[tid])["TransitGateways"][0][
                "State"
            ],
            lambda s: s == "available",
            timeout_s=300,
            interval_s=8,
        )

    attach_name = ctx.unique_name("sim2real-peer-attach-")
    attach_id = ec2.create_transit_gateway_peering_attachment(
        TransitGatewayId=tgw_a,
        PeerTransitGatewayId=tgw_b,
        PeerAccountId=account_id,
        PeerRegion=peer_region,
        TagSpecifications=[
            {"ResourceType": "transit-gateway-attachment", "Tags": [{"Key": "Name", "Value": attach_name}]}
        ],
    )["TransitGatewayPeeringAttachment"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(lambda: _delete_peering(ec2, attach_id, teardown_deadline))
    # Runs first (LIFO): the accepter side ends a still-pending attachment by rejecting it.
    ctx.on_cleanup(lambda: _settle_accepter(ec2_peer, attach_id, teardown_deadline))

    _poll_until(
        lambda: _peering_state(ec2_peer, attach_id),
        lambda s: s == "pendingAcceptance",
        timeout_s=_body_budget(ctx, 240.0),
        interval_s=2,
    )

    # --- error boundary: DryRun on the real pendingAcceptance attachment ---
    # Even though DescribeTransitGatewayPeeringAttachments already showed the attachment as
    # pendingAcceptance above, under this batch's heavy concurrent EC2 mutation load the mutating
    # control plane behind Reject/Accept can lag briefly behind the read path. Retry across that
    # eventual-consistency NotFound, but keep the budget modest -- the overall check shares its
    # harness ceiling with the TGW-creation contention retries above, so an over-generous retry
    # here can single-handedly blow that ceiling.
    code, message = _error_code_retrying(
        lambda: ec2_peer.reject_transit_gateway_peering_attachment(DryRun=True, TransitGatewayAttachmentId=attach_id),
        retry_code="InvalidTransitGatewayAttachmentID.NotFound",
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert code == "DryRunOperation", f"expected DryRunOperation, got {code}"
    expected_message = "Request would have succeeded, but DryRun flag is set."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # --- success path: reject transitions pendingAcceptance -> rejected ---
    resp = _retry_notfound(
        lambda: ec2_peer.reject_transit_gateway_peering_attachment(TransitGatewayAttachmentId=attach_id),
        timeout_s=180.0,
        interval_s=5.0,
    )
    # The Reject response reports the in-progress state; the read below sees it settle.
    reject_state = resp["TransitGatewayPeeringAttachment"]["State"]
    assert reject_state == "rejecting", f"expected rejecting, got {reject_state}"

    final_state = _poll_until(
        lambda: _peering_state(ec2_peer, attach_id),
        lambda s: s == "rejected",
        timeout_s=_body_budget(ctx, 180.0),
        interval_s=2,
    )
    assert final_state == "rejected", final_state


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    return None


def _error_code_retrying(fn, *, retry_code, timeout_s=60.0, interval_s=3.0):
    """Like _error_code, but transparently retries the call while it keeps failing with
    ``retry_code`` (an eventual-consistency 404 immediately after creation), returning the first
    *other* error as (code, message); a success raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == retry_code and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return code, exc.response["Error"]["Message"]
        raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _retry_notfound(fn, *, timeout_s=60.0, interval_s=3.0):
    """Retry a mutating call while it fails with the transit gateway attachment's
    eventual-consistency NotFound, re-raising any other error immediately."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if (
                exc.response["Error"]["Code"] == "InvalidTransitGatewayAttachmentID.NotFound"
                and time.monotonic() < deadline
            ):
                time.sleep(interval_s)
                continue
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last value: {last!r}")


def _create_tgw_with_retry(ec2, *, description, deadline, interval_s=15.0):
    """See note above: retry CreateTransitGateway across TransitGatewayLimitExceeded (a low,
    account-wide quota under contention from this batch's concurrent checks) instead of failing
    outright on transient contention. ``deadline`` is an absolute ``time.monotonic()`` value
    SHARED across both of this check's create calls, so the combined contention-wait is capped
    regardless of how it's split between them."""
    while True:
        try:
            return ec2.create_transit_gateway(
                Description=description,
                TagSpecifications=[
                    {"ResourceType": "transit-gateway", "Tags": [{"Key": "Name", "Value": description}]}
                ],
            )["TransitGateway"]["TransitGatewayId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "TransitGatewayLimitExceeded" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _body_budget(ctx, cap_s):
    """cap_s, bounded by the run's remaining time less 10 s so the poll fails with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 10.0))


def _peering_state(client, attach_id):
    """The attachment's State in client's region; None while it is not yet visible there."""
    try:
        atts = client.describe_transit_gateway_peering_attachments(TransitGatewayAttachmentIds=[attach_id])[
            "TransitGatewayPeeringAttachments"
        ]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidTransitGatewayAttachmentID.NotFound":
            raise
        return None
    return atts[0]["State"] if atts else None


# budget.cleanup_timeout for behavioral/ec2, one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 900.0
# States that hold no TGW: AWS removes a rejected or failed attachment without a delete.
_PEERING_DONE = (None, "deleted", "rejected", "failed")


def _wait_peering_done(client, attach_id, deadline):
    while _peering_state(client, attach_id) not in _PEERING_DONE:
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"peering attachment {attach_id} still {_peering_state(client, attach_id)!r} at the cleanup deadline"
            )
        time.sleep(2)


def _settle_accepter(ec2_peer, attach_id, shared):
    """Accepter-side teardown: reject an attachment still pendingAcceptance, then wait until the
    accepter TGW's view of it holds nothing."""
    deadline = shared.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S)
    if _peering_state(ec2_peer, attach_id) == "pendingAcceptance":
        ec2_peer.reject_transit_gateway_peering_attachment(TransitGatewayAttachmentId=attach_id)
    _wait_peering_done(ec2_peer, attach_id, deadline)


def _delete_peering(ec2, attach_id, shared):
    """Requester-side teardown: delete a still-live attachment, then wait until it holds nothing."""
    deadline = shared.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S)
    if _peering_state(ec2, attach_id) not in _PEERING_DONE + ("deleting", "rejecting", "failing"):
        try:
            ec2.delete_transit_gateway_peering_attachment(TransitGatewayAttachmentId=attach_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidTransitGatewayAttachmentID.NotFound":
                raise
    _wait_peering_done(ec2, attach_id, deadline)


def _delete_tgw(ec2, tgw_id, shared):
    """Delete the TGW; retry IncorrectState while its peering attachments are still deleting, and
    throttling, every 2 s to the cleanup deadline. A gone TGW is done."""
    deadline = shared.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S)
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
