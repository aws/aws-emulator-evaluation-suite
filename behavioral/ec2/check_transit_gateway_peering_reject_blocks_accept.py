"""transit-gateway-peering-reject-blocks-accept."""
from __future__ import annotations

import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "transit-gateway-peering-reject-blocks-accept"
GROUP = "state-machine"
SERVICES = ["ec2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """After RejectTransitGatewayPeeringAttachment, AcceptTransitGatewayPeeringAttachment fails with
    IncorrectState and its exact message and the attachment stays "rejected"; accepting a second
    pendingAcceptance attachment makes it "available"."""
    ec2 = ctx.client("ec2")
    # Transit Gateway peering is inherently cross-region: the peer TGW must live in a
    # different region than ctx.region, so a second region is picked dynamically rather
    # than pinned to one literal.
    peer_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"

    try:
        ec2_peer = _peer_region_client(ctx, peer_region)
        ec2_peer.describe_regions(RegionNames=[peer_region])
    except Exception as exc:  # pragma: no cover - environment dependent
        raise AssertionError(f"peer region {peer_region} not reachable with current credentials: {exc}")

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-tgwpeer-")

    tgw_a = _create_tgw(ctx, ec2, name + "-a")
    tgw_b = _create_tgw(ctx, ec2_peer, name + "-b")

    # ---- Negative: create a peering attachment, reject it, then attempt to accept it ----
    attach_id = ec2.create_transit_gateway_peering_attachment(
        TransitGatewayId=tgw_a,
        PeerTransitGatewayId=tgw_b,
        PeerAccountId=account_id,
        PeerRegion=peer_region,
    )["TransitGatewayPeeringAttachment"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(lambda: _delete_peering_attachment(ec2_peer, attach_id))

    def _accepter_state():
        return _describe_attachment_state(ec2_peer, attach_id)

    _poll_until(_accepter_state, lambda s: s == "pendingAcceptance", timeout_s=180, interval_s=5)

    ec2_peer.reject_transit_gateway_peering_attachment(TransitGatewayAttachmentId=attach_id)
    _poll_until(_accepter_state, lambda s: s == "rejected", timeout_s=180, interval_s=5)

    code, message = _error_code(
        lambda: ec2_peer.accept_transit_gateway_peering_attachment(
            TransitGatewayAttachmentId=attach_id
        )
    )
    assert code == "IncorrectState", (
        f"expected AcceptTransitGatewayPeeringAttachment on a rejected attachment to fail with "
        f"IncorrectState, got {code!r}"
    )
    assert message == f"{attach_id} is in invalid state", (
        f"expected EC2's exact invalid-state message for {attach_id!r}, got {message!r}"
    )
    # The rejection is durable: state is still 'rejected', not accepted.
    state_after_accept_attempt = _accepter_state()
    assert state_after_accept_attempt == "rejected", (
        f"expected state to remain 'rejected' after the blocked accept attempt, "
        f"got {state_after_accept_attempt!r}"
    )

    # ---- Positive control: a fresh attachment in pendingAcceptance CAN be accepted ----
    tgw_c = _create_tgw(ctx, ec2_peer, name + "-c")
    attach2_id = ec2.create_transit_gateway_peering_attachment(
        TransitGatewayId=tgw_a,
        PeerTransitGatewayId=tgw_c,
        PeerAccountId=account_id,
        PeerRegion=peer_region,
    )["TransitGatewayPeeringAttachment"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(lambda: _delete_peering_attachment(ec2_peer, attach2_id))

    def _accepter2_state():
        return _describe_attachment_state(ec2_peer, attach2_id)

    _poll_until(_accepter2_state, lambda s: s == "pendingAcceptance", timeout_s=180, interval_s=5)
    ec2_peer.accept_transit_gateway_peering_attachment(TransitGatewayAttachmentId=attach2_id)
    accepted_state = _poll_until(
        _accepter2_state, lambda s: s in ("available", "failed", "rejected"), timeout_s=600, interval_s=5
    )
    assert accepted_state == "available", (
        f"expected a fresh pendingAcceptance attachment to accept successfully, "
        f"got state {accepted_state!r}"
    )


def _peer_region_client(ctx, region: str):
    """The peer-side EC2 client, pinned to the TARGET under test.

    `ctx.client(region=...)` keeps the target's endpoint, credentials and TLS settings and only
    re-pins the region.

    Note the residual fidelity limitation: against an emulator all regions share the one endpoint,
    so `region` changes only the signing/requested region, not the host. A cross-region peering
    check therefore exercises an emulator's region *modelling* only as far as it honours the
    requested region in the request itself.
    """
    return ctx.client("ec2", region=region)


def _describe_attachment_state(client, attachment_id: str):
    """A cross-region peering attachment can briefly answer NotFound from the peer region's own
    endpoint just after creation -- real AWS has not yet propagated it there -- even though the
    requester side already sees it. Read as 'not yet visible' (None), same as an empty result, so
    the caller's own bounded poll absorbs the propagation lag instead of crashing on it."""
    from botocore.exceptions import ClientError

    try:
        atts = client.describe_transit_gateway_peering_attachments(
            TransitGatewayAttachmentIds=[attachment_id]
        )["TransitGatewayPeeringAttachments"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "InvalidTransitGatewayAttachmentID.NotFound":
            return None
        raise
    return atts[0]["State"] if atts else None


def _create_tgw(ctx, client, name: str) -> str:
    tgw_id = client.create_transit_gateway(
        Description=name,
        TagSpecifications=[
            {
                "ResourceType": "transit-gateway",
                "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
            }
        ],
    )["TransitGateway"]["TransitGatewayId"]
    ctx.on_cleanup(lambda: _delete_tgw(client, tgw_id))

    def _state():
        return client.describe_transit_gateways(TransitGatewayIds=[tgw_id])["TransitGateways"][0][
            "State"
        ]

    _poll_until(_state, lambda s: s == "available", timeout_s=300, interval_s=5)
    return tgw_id


def _error_code(fn: Callable[[], Any]):
    """Call fn(); return its botocore (code, message). An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_peering_attachment(client, attachment_id: str) -> None:
    """Teardown: delete the attachment unless it is already rejected, and wait until it no longer
    holds either transit gateway, so the gateways' own deletes succeed."""
    from botocore.exceptions import ClientError

    if _describe_attachment_state(client, attachment_id) not in (None, "rejected", "deleting", "deleted"):
        try:
            client.delete_transit_gateway_peering_attachment(TransitGatewayAttachmentId=attachment_id)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidTransitGatewayAttachmentID.NotFound":
                raise
    _poll_until(
        lambda: _describe_attachment_state(client, attachment_id),
        lambda s: s in (None, "rejected", "deleted"),
        timeout_s=600,
        interval_s=10,
    )


def _delete_tgw(client, tgw_id: str) -> None:
    """Teardown: retry while attachments finish deleting, so the transit gateway never leaks."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 600
    while True:
        try:
            client.delete_transit_gateway(TransitGatewayId=tgw_id)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "InvalidTransitGatewayID.NotFound":
                return
            if code not in ("IncorrectState", "DependencyViolation") or time.monotonic() >= deadline:
                raise
        time.sleep(10)


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
