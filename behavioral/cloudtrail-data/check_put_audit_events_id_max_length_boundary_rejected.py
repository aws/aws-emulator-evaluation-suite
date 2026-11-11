"""put-audit-events-id-max-length-boundary-rejected."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-audit-events-id-max-length-boundary-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudtrail-data"]

_MAX_ID_LEN = 128  # documented AuditEvent.id maximum length


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An AuditEvent id of 129 characters is refused with ValidationException and the exact max-length
    message, while a 128-character id to the same nonexistent channel passes length validation and gets
    ChannelNotFound with the exact not-found message."""
    cloudtrail_data = ctx.client("cloudtrail-data")
    account_id = _account_id(ctx)
    channel_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:channel/{uuid.uuid4()}"
    not_found_message = f"The channel {channel_arn} could not be found."

    over_max_id = "a" * (_MAX_ID_LEN + 1)
    code, message = _error(
        lambda: cloudtrail_data.put_audit_events(
            channelArn=channel_arn,
            auditEvents=[{"id": over_max_id, "eventData": json.dumps(_base_event_data(ctx))}],
        )
    )
    assert code == "ValidationException", (
        f"unexpected error code for a {_MAX_ID_LEN + 1}-char id: {code!r} ({message!r})"
    )
    assert message == (
        f"1 validation error detected: Value '{over_max_id}' at "
        f"'auditEvents.1.member.id' failed to satisfy constraint: "
        f"Member must have length less than or equal to {_MAX_ID_LEN}"
    ), f"unexpected id-length violation message: {message!r}"

    # Control: an id AT the 128-char boundary is not rejected for length -- it fails only
    # for the unrelated ChannelNotFound reason (no real channel exists).
    at_max_id = "a" * _MAX_ID_LEN
    code, message = _error(
        lambda: cloudtrail_data.put_audit_events(
            channelArn=channel_arn,
            auditEvents=[{"id": at_max_id, "eventData": json.dumps(_base_event_data(ctx))}],
        )
    )
    assert code == "ChannelNotFound", (
        f"expected a {_MAX_ID_LEN}-char (at-boundary) id to pass length validation and fail "
        f"only on ChannelNotFound, got {code!r} ({message!r})"
    )
    assert message == not_found_message, f"unexpected resolution message at the id boundary: {message!r}"


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
