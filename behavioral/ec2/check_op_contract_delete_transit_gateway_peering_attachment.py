"""op-contract-deleteTransitGatewayPeeringAttachment."""
from __future__ import annotations

import concurrent.futures
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-deleteTransitGatewayPeeringAttachment"
GROUP = "error-semantics"
SERVICES = ["ec2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteTransitGatewayPeeringAttachment deletes a peering attachment in pendingAcceptance, which
    reaches deleted and stays deleted on a repeat delete; a nonexistent attachment ID fails with
    InvalidTransitGatewayAttachmentID.NotFound and its exact message."""
    ec2 = ctx.client("ec2")
    sts = ctx.client("sts")
    name = ctx.unique_name("sim2real-behav-tgwpeer-")
    account_id = sts.get_caller_identity()["Account"]

    # Build both sides concurrently -- sequentially this pair of CreateTransitGateway calls (each
    # potentially retrying through a transient TransitGatewayLimitExceeded) could by itself eat the
    # whole per-check budget before any peering work even starts.
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        requester_fut = pool.submit(_create_tgw, ctx, ec2, name + "req")
        accepter_fut = pool.submit(_create_tgw, ctx, ec2, name + "acc")
        requester_id = requester_fut.result()
        accepter_id = accepter_fut.result()

    created = _retry_on_incorrect_state(
        lambda: ec2.create_transit_gateway_peering_attachment(
            TransitGatewayId=requester_id,
            PeerTransitGatewayId=accepter_id,
            PeerAccountId=account_id,
            PeerRegion=ctx.region,
            TagSpecifications=[
                {"ResourceType": "transit-gateway-attachment", "Tags": [{"Key": "Name", "Value": name}]}
            ],
        )
    )
    peering_id = created["TransitGatewayPeeringAttachment"]["TransitGatewayAttachmentId"]
    ctx.on_cleanup(
        lambda: _best_effort(
            lambda: ec2.delete_transit_gateway_peering_attachment(TransitGatewayAttachmentId=peering_id)
        )
    )

    # A peering attachment whose two sides belong to the same account never reaches "available": the
    # requester cannot accept its own request, so the delete is exercised on pendingAcceptance.
    pending_state = _wait_peering_state(ec2, peering_id, "pendingAcceptance", timeout_s=120.0)
    assert pending_state == "pendingAcceptance", f"peering attachment never reached pendingAcceptance (last={pending_state})"

    delete_resp = ec2.delete_transit_gateway_peering_attachment(TransitGatewayAttachmentId=peering_id)
    assert delete_resp["TransitGatewayPeeringAttachment"]["State"] in ("deleting", "deleted")

    final_state = _wait_peering_state(ec2, peering_id, "deleted", timeout_s=180.0, treat_notfound_as="deleted")
    assert final_state == "deleted", f"peering attachment never reached deleted (last={final_state})"

    # A second delete of the same deleted ID succeeds as a no-op and must leave the attachment
    # deleted, neither resurrected nor recreated.
    ec2.delete_transit_gateway_peering_attachment(TransitGatewayAttachmentId=peering_id)
    still_gone = _wait_peering_state(ec2, peering_id, "deleted", timeout_s=30.0, treat_notfound_as="deleted")
    assert still_gone == "deleted", f"double-delete resurrected the attachment (state={still_gone})"

    bogus_attachment_id = "tgw-attach-0123456789abcdef0"
    error = _error(
        lambda: ec2.delete_transit_gateway_peering_attachment(TransitGatewayAttachmentId=bogus_attachment_id)
    )
    assert error["Code"] == "InvalidTransitGatewayAttachmentID.NotFound", error
    assert error.get("Message") == f"Transit Gateway Attachment {bogus_attachment_id} was deleted or does not exist.", error


def _poll(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn):
    """Call fn() and return its botocore Error dict; a call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _retry_on_incorrect_state(fn, timeout_s=180.0, interval_s=10.0):
    """A transit gateway that just reported describe-state "available" can still briefly
    reject dependent operations (e.g. CreateTransitGatewayPeeringAttachment) with
    IncorrectState while the backend finishes propagating that state internally. Poll
    through that narrow window instead of treating it as fatal."""
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


def _wait_peering_state(ec2, peering_id, target, timeout_s=180.0, treat_notfound_as=None):
    targets = {target} if isinstance(target, str) else set(target)

    def probe():
        try:
            resp = ec2.describe_transit_gateway_peering_attachments(TransitGatewayAttachmentIds=[peering_id])
            atts = resp["TransitGatewayPeeringAttachments"]
            if not atts:
                return treat_notfound_as
            return atts[0]["State"]
        except ClientError as exc:
            if treat_notfound_as and "NotFound" in exc.response["Error"]["Code"]:
                return treat_notfound_as
            raise

    return _poll(probe, lambda s: s in targets, timeout_s=timeout_s)


def _reclaim_stale_tgws(ec2, min_age_s=300.0):
    """Free transit gateway quota held by stale gateways of this suite: delete only an "available"
    gateway with this suite's Name-tag prefix, no live attachment and older than min_age_s, which stays
    below the 900 s check deadline yet above the moment between gateway available and attachment."""
    try:
        tgws = ec2.describe_transit_gateways(Filters=[{"Name": "state", "Values": ["available"]}])[
            "TransitGateways"
        ]
    except ClientError:
        return
    now = datetime.now(timezone.utc)
    for tgw in tgws:
        name_tag = next((t["Value"] for t in tgw.get("Tags", []) if t["Key"] == "Name"), "")
        if not name_tag.startswith("sim2real-behav-"):
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


def _retry_on_tgw_limit(ec2, fn, timeout_s=600.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "TransitGatewayLimitExceeded" or time.monotonic() >= deadline:
                raise
            _reclaim_stale_tgws(ec2)
            time.sleep(interval_s)


def _create_tgw(ctx, ec2, name):
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


def _best_effort(fn):
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

