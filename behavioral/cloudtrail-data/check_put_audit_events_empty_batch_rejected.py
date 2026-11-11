"""put-audit-events-empty-batch-rejected."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-audit-events-empty-batch-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudtrail-data"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """With client-side validation off, a non-empty batch to a nonexistent channel gets ChannelNotFound and an
    empty auditEvents list to the same channel gets ValidationException, each with AWS's exact message:
    the length-1 minimum is enforced server-side before channel resolution."""
    account_id = _account_id(ctx)
    channel_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:channel/{uuid.uuid4()}"
    unvalidated = ctx.client("cloudtrail-data", config=Config(parameter_validation=False))

    # Positive control: the channel does not exist, but a well-formed non-empty batch
    # against it still reaches channel resolution -- proves the unvalidated client, the
    # credentials and the service itself are otherwise healthy.
    code, message = _error(
        lambda: unvalidated.put_audit_events(
            channelArn=channel_arn,
            auditEvents=[{"id": str(uuid.uuid4()), "eventData": json.dumps(_base_event_data(ctx))}],
        )
    )
    assert code == "ChannelNotFound", (
        f"expected ChannelNotFound for a non-empty batch against a nonexistent channel, got {code!r}"
    )
    assert message == f"The channel {channel_arn} could not be found.", (
        f"unexpected resolution message for a non-empty batch: {message!r}"
    )

    # Same channel ARN, empty batch: the constraint layer must reject it before channel
    # resolution is even attempted.
    code, message = _error(
        lambda: unvalidated.put_audit_events(channelArn=channel_arn, auditEvents=[])
    )
    assert code == "ValidationException", (
        f"unexpected server-side error code for an empty auditEvents list: {code!r}"
    )
    assert message == (
        "1 validation error detected: Value '[]' at 'auditEvents' failed to satisfy "
        "constraint: Member must have length greater than or equal to 1"
    ), f"unexpected empty-batch violation message: {message!r}"


def _error(fn):
    """(Error.Code, Error.Message) for the ClientError fn() raises; a SUCCESS raises."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected a rejection, got a successful response: {resp!r}")


def _now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _base_event_data(ctx) -> dict:
    return {
        "version": "1.0",
        "userIdentity": {"type": "CustomUserIdentity", "principalId": "sim2real-principal"},
        "eventSource": "sim2real.example.com",
        "eventName": "Sim2RealTestAction",
        "eventTime": _now_ts(),
        "UID": f"sim2real-uid-{uuid.uuid4().hex}",
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
