"""put-audit-events-id-pattern-violation-rejected."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-audit-events-id-pattern-violation-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudtrail-data"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """With client-side validation off, an AuditEvent id containing spaces is refused with ValidationException
    and the exact [-_A-Za-z0-9]+ pattern message, while a well-formed id to the same nonexistent channel
    gets ChannelNotFound with the exact not-found message."""
    cloudtrail_data = ctx.client("cloudtrail-data")
    unvalidated_cloudtrail_data = ctx.client(
        "cloudtrail-data", config=Config(parameter_validation=False)
    )
    account_id = _account_id(ctx)
    channel_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:channel/{uuid.uuid4()}"

    # Positive control: a well-formed id against this (never-created) channel reaches
    # the server and fails only for channel-existence reasons.
    good_code, good_message = _error(
        lambda: cloudtrail_data.put_audit_events(
            channelArn=channel_arn,
            auditEvents=[
                {"id": f"sim2real-{uuid.uuid4().hex}", "eventData": json.dumps(_base_event_data(ctx))}
            ],
        )
    )
    assert good_code == "ChannelNotFound", (
        f"expected a well-formed id against a nonexistent channel to fail with "
        f"ChannelNotFound (establishing the request reaches the server), got {good_code!r}"
    )
    assert good_message == f"The channel {channel_arn} could not be found.", (
        f"unexpected resolution message for a well-formed id: {good_message!r}"
    )

    # Negative: the identical (nonexistent) channel, but an id that violates the
    # documented [-_A-Za-z0-9]+ pattern, sent past botocore's own client-side check.
    bad_id = "sim2real id with spaces"  # violates [-_A-Za-z0-9]+
    bad_code, bad_message = _error(
        lambda: unvalidated_cloudtrail_data.put_audit_events(
            channelArn=channel_arn,
            auditEvents=[{"id": bad_id, "eventData": json.dumps(_base_event_data(ctx))}],
        )
    )
    assert bad_code == "ValidationException", (
        f"expected a server-side ValidationException for a pattern-violating id, got {bad_code!r}"
    )
    assert bad_message == (
        f"1 validation error detected: Value '{bad_id}' at 'auditEvents.1.member.id' failed to "
        "satisfy constraint: Member must satisfy regular expression pattern: [-_A-Za-z0-9]+"
    ), f"unexpected id-pattern violation message: {bad_message!r}"
    assert bad_code != good_code, (
        "expected the id-pattern rejection to be distinguishable from the "
        "channel-not-found rejection, but both came back as the same code"
    )


def _error(fn):
    """(Error.Code, Error.Message) for the ClientError fn() raises; a SUCCESS raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError("expected a ClientError, but the call succeeded")


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
