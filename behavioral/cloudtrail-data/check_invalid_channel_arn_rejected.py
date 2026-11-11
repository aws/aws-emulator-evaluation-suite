"""invalid-channel-arn-rejected."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-channel-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudtrail-data"]

_BAD_ARN = "The specified channel ARN is not a valid channel ARN."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutAuditEvents with an ARN lacking the channel/<id> resource segment is refused with InvalidChannelARN
    and its exact message, while a well-formed absent channel ARN gets ChannelNotFound with the exact
    not-found message: a malformed reference is distinct from a missing channel."""
    cloudtrail_data = ctx.client("cloudtrail-data")
    account_id = _account_id(ctx)

    # Starts with "arn:" (satisfies the loose SDK-level ^arn:.*$ pattern) but names the
    # wrong resource type -- not a real "channel/<id>" CloudTrail channel ARN.
    malformed_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:not-a-channel-resource"
    code, message = _error(
        lambda: cloudtrail_data.put_audit_events(
            channelArn=malformed_arn,
            auditEvents=[_event(ctx)],
        )
    )
    assert code == "InvalidChannelARN", f"expected InvalidChannelARN, got {code!r} ({message!r})"
    assert message == _BAD_ARN, f"unexpected malformed-ARN message: {message!r}"

    # Positive control on the same wiring: a well-formed ARN that merely names no real
    # channel reaches resolution rather than tripping the ARN-shape check, proving the
    # rejection above is about the malformed resource segment specifically -- not a
    # blanket refusal of every PutAuditEvents call.
    absent_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:channel/{uuid.uuid4()}"
    code, message = _error(
        lambda: cloudtrail_data.put_audit_events(
            channelArn=absent_arn,
            auditEvents=[_event(ctx)],
        )
    )
    assert code == "ChannelNotFound", f"expected ChannelNotFound for a well-formed absent ARN, got {code!r} ({message!r})"
    assert message == f"The channel {absent_arn} could not be found.", f"unexpected resolution message: {message!r}"


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


def _event(ctx) -> dict:
    return {
        "id": f"sim2real-{uuid.uuid4().hex}",
        "eventData": json.dumps(
            {
                "version": "1.0",
                "userIdentity": {"type": "CustomUserIdentity", "principalId": "sim2real-principal"},
                "eventSource": "sim2real.example.com",
                "eventName": "Sim2RealTestAction",
                "eventTime": _now_ts(),
                "UID": f"sim2real-uid-{uuid.uuid4().hex}",
                "recipientAccountId": _account_id(ctx),
            }
        ),
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
