"""channel-not-found-rejected."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "channel-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudtrail-data"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutAuditEvents to a well-formed channel ARN that names no channel is refused with ChannelNotFound and
    the exact "The channel <arn> could not be found." message, while an ARN without a channel/<id>
    segment gets InvalidChannelARN: the service resolves the channel rather than accepting any ARN."""
    cloudtrail_data = ctx.client("cloudtrail-data")

    account_id = _account_id(ctx)
    batch = [{"id": f"sim2real-{uuid.uuid4().hex}", "eventData": json.dumps(_base_event_data(ctx))}]

    malformed_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:not-a-channel-resource"
    malformed_code, _ = _error(
        lambda: cloudtrail_data.put_audit_events(channelArn=malformed_arn, auditEvents=batch)
    )
    assert malformed_code == "InvalidChannelARN", f"expected InvalidChannelARN, got {malformed_code!r}"

    nonexistent_arn = (
        f"arn:aws:cloudtrail:{ctx.region}:{account_id}:channel/00000000-0000-0000-0000-000000000000"
    )
    code, message = _error(
        lambda: cloudtrail_data.put_audit_events(channelArn=nonexistent_arn, auditEvents=batch)
    )
    assert code == "ChannelNotFound", f"expected ChannelNotFound, got {code!r}"
    assert message == f"The channel {nonexistent_arn} could not be found.", (
        f"unexpected ChannelNotFound message: {message!r}"
    )


def _error(fn):
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
