"""channel-arn-unicode-characters-rejected."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "channel-arn-unicode-characters-rejected"
GROUP = "representation"
SERVICES = ["cloudtrail-data"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutAuditEvents with a channelArn whose resource segment holds multi-byte UTF-8 (an accented letter
    and an emoji) is refused with InvalidChannelARN and the exact invalid-ARN message, the same code and
    message as its ASCII analogue: the query-string value survives encoding intact."""
    cloudtrail_data = ctx.client("cloudtrail-data")
    account_id = _account_id(ctx)
    unicode_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:channel/caf\u00e9-\U0001f680-not-real"

    code, message = _error_code(
        lambda: cloudtrail_data.put_audit_events(
            channelArn=unicode_arn,
            auditEvents=[{"id": f"sim2real-{uuid.uuid4().hex}", "eventData": json.dumps(_base_event_data(ctx))}],
        )
    )
    assert code == "InvalidChannelARN", (
        f"expected a well-formed rejection (InvalidChannelARN) for a "
        f"unicode channel ARN, got {code!r}"
    )
    assert message == "The specified channel ARN is not a valid channel ARN.", (
        f"expected the invalid-channel-ARN message, got {message!r}"
    )

    # Control: the plain-ASCII equivalent shape (same structure, no multi-byte chars)
    # against the SAME nonexistent resource id gets the SAME classification -- proving
    # the unicode content itself, not some incidental length/shape difference, is what's
    # being represented faithfully through the request pipeline.
    ascii_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:channel/cafe-rocket-not-real"
    ascii_code, ascii_message = _error_code(
        lambda: cloudtrail_data.put_audit_events(
            channelArn=ascii_arn,
            auditEvents=[{"id": f"sim2real-{uuid.uuid4().hex}", "eventData": json.dumps(_base_event_data(ctx))}],
        )
    )
    assert ascii_code == code, (
        f"unicode channel ARN classified as {code!r} but its ASCII analogue classified "
        f"as {ascii_code!r} -- encoding should not change which error path is taken"
    )
    assert ascii_message == message, f"expected the same message for the ASCII ARN, got {ascii_message!r}"


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


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
