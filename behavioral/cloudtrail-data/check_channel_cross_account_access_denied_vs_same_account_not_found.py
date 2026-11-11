"""channel-cross-account-access-denied-vs-same-account-not-found."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "channel-cross-account-access-denied-vs-same-account-not-found"
GROUP = "overly-permissive"
SERVICES = ["cloudtrail-data"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutAuditEvents on a channel ARN in a different account fails with a generic AccessDenied at the
    authorization layer, while the same channel id in the caller's account fails ChannelNotFound.
    """
    cloudtrail_data = ctx.client("cloudtrail-data")
    own_account_id = _account_id(ctx)

    # A documentation-placeholder account id that differs from the caller's.
    foreign_account_id = "111122223333" if own_account_id != "111122223333" else "444455556666"
    channel_id = str(uuid.uuid4())
    foreign_arn = f"arn:aws:cloudtrail:{ctx.region}:{foreign_account_id}:channel/{channel_id}"

    cross_code, cross_message, cross_status = _error(
        lambda: cloudtrail_data.put_audit_events(
            channelArn=foreign_arn,
            auditEvents=[{"id": f"sim2real-{uuid.uuid4().hex}", "eventData": json.dumps(_base_event_data(ctx))}],
        )
    )
    assert cross_code == "AccessDeniedException", (
        f"expected AccessDeniedException (IAM authorization layer) for a cross-account "
        f"channel ARN, got {cross_code!r} ({cross_message!r})"
    )
    assert cross_status == 403, f"expected HTTP 403 for a cross-account channel ARN, got {cross_status!r}"
    assert "cloudtrail-data:PutAuditEvents" in cross_message, (
        f"the denial does not name the action it refused: {cross_message!r}"
    )
    assert "could not be found" not in cross_message, (
        f"the denial leaks a resolution verdict for another account's channel: {cross_message!r}"
    )

    # Control: the IDENTICAL channel id, but under the CALLER's own account, gets PAST
    # authorization and is rejected with the resource-specific ChannelNotFound instead --
    # isolating the account segment as the only thing that changed between the two calls.
    own_account_arn = f"arn:aws:cloudtrail:{ctx.region}:{own_account_id}:channel/{channel_id}"
    own_code, own_message, own_status = _error(
        lambda: cloudtrail_data.put_audit_events(
            channelArn=own_account_arn,
            auditEvents=[{"id": f"sim2real-{uuid.uuid4().hex}", "eventData": json.dumps(_base_event_data(ctx))}],
        )
    )
    assert own_code == "ChannelNotFound", (
        f"expected ChannelNotFound for a same-account nonexistent channel, got {own_code!r} ({own_message!r})"
    )
    assert own_status == 400, f"expected HTTP 400 for a same-account nonexistent channel, got {own_status!r}"
    assert own_message == f"The channel {own_account_arn} could not be found.", (
        f"unexpected resolution message: {own_message!r}"
    )
    assert own_code != cross_code, (
        "expected the cross-account (authorization-layer) and same-account "
        "(resource-existence-layer) rejections to be DIFFERENT error codes"
    )


def _error(fn):
    """(Error.Code, Error.Message, HTTP status) for the ClientError fn() raises. A SUCCESS
    raises rather than returning a falsy sentinel that would read as a mere code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), err.get("Message") or "", status
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
