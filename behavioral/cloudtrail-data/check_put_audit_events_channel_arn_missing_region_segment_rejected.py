"""put-audit-events-channel-arn-missing-region-segment-rejected."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-audit-events-channel-arn-missing-region-segment-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudtrail-data"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A channelArn with an EMPTY region segment (double colon: '...:cloudtrail::123...')
    is a structurally malformed ARN -- rejected, distinctly from a well-formed ARN with
    a real region that simply names a nonexistent channel."""
    cloudtrail_data = ctx.client("cloudtrail-data")
    account_id = _account_id(ctx)

    empty_region_arn = f"arn:aws:cloudtrail::{account_id}:channel/{uuid.uuid4()}"
    empty_region_code, empty_region_message = _error(
        lambda: cloudtrail_data.put_audit_events(
            channelArn=empty_region_arn,
            auditEvents=[{"id": f"sim2real-{uuid.uuid4().hex}", "eventData": json.dumps(_base_event_data(ctx))}],
        )
    )
    assert empty_region_code == "InvalidChannelARN", (
        f"expected InvalidChannelARN for a channel ARN with an empty region segment, "
        f"got {empty_region_code!r} ({empty_region_message!r})"
    )
    assert empty_region_message == "The specified channel ARN is not a valid channel ARN.", (
        f"unexpected message for an empty-region channel ARN: {empty_region_message!r}"
    )

    # Control: the identical resource id, with the real region filled in, is a
    # well-formed-but-nonexistent channel -- ChannelNotFound.
    real_region_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:channel/{uuid.uuid4()}"
    real_region_code, real_region_message = _error(
        lambda: cloudtrail_data.put_audit_events(
            channelArn=real_region_arn,
            auditEvents=[{"id": f"sim2real-{uuid.uuid4().hex}", "eventData": json.dumps(_base_event_data(ctx))}],
        )
    )
    assert real_region_code == "ChannelNotFound", (
        f"expected ChannelNotFound for a well-formed channel ARN with a real region, "
        f"got {real_region_code!r} ({real_region_message!r})"
    )
    assert real_region_message == f"The channel {real_region_arn} could not be found.", (
        f"unexpected message for a well-formed absent channel ARN: {real_region_message!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) for the ClientError fn() raises. A SUCCESS raises rather than
    returning a falsy sentinel that would read as a mere code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError("the call unexpectedly SUCCEEDED; real AWS rejects it")


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _base_event_data(ctx, **overrides) -> dict:
    data = {
        "version": "1.0",
        "userIdentity": {"type": "CustomUserIdentity", "principalId": "sim2real-principal"},
        "eventSource": "sim2real.example.com",
        "eventName": "Sim2RealTestAction",
        "eventTime": _now_ts(),
        "UID": f"sim2real-uid-{uuid.uuid4().hex}",
        "recipientAccountId": _account_id(ctx),
    }
    data.update(overrides)
    return data


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
