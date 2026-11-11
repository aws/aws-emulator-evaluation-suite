"""duplicated-audit-event-id-rejected."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "duplicated-audit-event-id-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudtrail-data"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutAuditEvents with two entries sharing one id, sent to a nonexistent channel, is refused with
    ChannelNotFound and the exact not-found message, identical to the same request with distinct ids:
    channel existence is validated before DuplicatedAuditEventId."""
    cloudtrail_data = ctx.client("cloudtrail-data")
    account_id = _account_id(ctx)
    nonexistent_arn = (
        f"arn:aws:cloudtrail:{ctx.region}:{account_id}:channel/{uuid.uuid4()}"
    )

    shared_id = f"sim2real-dup-{uuid.uuid4().hex}"
    duplicate_events = [
        {"id": shared_id, "eventData": json.dumps(_base_event_data(ctx, eventName="First"))},
        {"id": shared_id, "eventData": json.dumps(_base_event_data(ctx, eventName="Second"))},
    ]

    not_found = f"The channel {nonexistent_arn} could not be found."

    dup_code, dup_message = _error(
        lambda: cloudtrail_data.put_audit_events(channelArn=nonexistent_arn, auditEvents=duplicate_events)
    )
    assert dup_code == "ChannelNotFound", (
        f"expected channel-existence validation to dominate a shared-id request shape "
        f"against a nonexistent channel (ChannelNotFound), got {dup_code!r}"
    )
    assert dup_message == not_found, f"unexpected shared-id message: {dup_message!r}"

    # Control: the SAME nonexistent channel, with distinct (non-duplicated) ids, fails
    # with the identical error -- confirming the two request shapes are indistinguishable
    # until the channel itself is resolved.
    distinct_events = [
        {"id": f"sim2real-a-{uuid.uuid4().hex}", "eventData": json.dumps(_base_event_data(ctx, eventName="A"))},
        {"id": f"sim2real-b-{uuid.uuid4().hex}", "eventData": json.dumps(_base_event_data(ctx, eventName="B"))},
    ]
    notfound_code, notfound_message = _error(
        lambda: cloudtrail_data.put_audit_events(channelArn=nonexistent_arn, auditEvents=distinct_events)
    )
    assert notfound_code == "ChannelNotFound", (
        f"expected ChannelNotFound for distinct ids against a nonexistent channel, got {notfound_code!r}"
    )
    assert notfound_message == not_found, f"unexpected distinct-id message: {notfound_message!r}"
    assert notfound_code == dup_code, (
        "expected the duplicated-id and distinct-id requests against the same "
        "nonexistent channel to fail identically"
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
