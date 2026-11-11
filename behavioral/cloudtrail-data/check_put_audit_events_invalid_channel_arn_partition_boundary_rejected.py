"""put-audit-events-invalid-channel-arn-partition-boundary-rejected."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-audit-events-invalid-channel-arn-partition-boundary-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudtrail-data"]

_BAD_ARN = "The specified channel ARN is not a valid channel ARN."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutAuditEvents with a channel ARN in the aws-cn partition is refused with InvalidChannelARN and the
    exact invalid-ARN message, while the same shape in the aws partition gets ChannelNotFound with the
    exact not-found message."""
    cloudtrail_data = ctx.client("cloudtrail-data")
    account_id = _account_id(ctx)

    wrong_partition_arn = f"arn:aws-cn:cloudtrail:{ctx.region}:{account_id}:channel/{uuid.uuid4()}"
    wrong_partition_code, wrong_partition_message = _error(
        lambda: cloudtrail_data.put_audit_events(
            channelArn=wrong_partition_arn,
            auditEvents=[{"id": f"sim2real-{uuid.uuid4().hex}", "eventData": json.dumps(_base_event_data(ctx))}],
        )
    )
    assert wrong_partition_code == "InvalidChannelARN", (
        f"expected InvalidChannelARN for a wrong-partition channel ARN, got {wrong_partition_code!r}"
    )
    assert wrong_partition_message == _BAD_ARN, f"unexpected malformed-ARN message: {wrong_partition_message!r}"

    # Control: the identical resource id in the CALLER's actual partition ("aws") is a
    # well-formed, same-account, simply-nonexistent channel -- ChannelNotFound.
    same_partition_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:channel/{uuid.uuid4()}"
    same_partition_code, same_partition_message = _error(
        lambda: cloudtrail_data.put_audit_events(
            channelArn=same_partition_arn,
            auditEvents=[{"id": f"sim2real-{uuid.uuid4().hex}", "eventData": json.dumps(_base_event_data(ctx))}],
        )
    )
    assert same_partition_code == "ChannelNotFound", (
        f"expected ChannelNotFound for a same-partition nonexistent channel, got {same_partition_code!r}"
    )
    assert same_partition_message == f"The channel {same_partition_arn} could not be found.", (
        f"unexpected resolution message: {same_partition_message!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) for the ClientError fn() raises. An unexpected SUCCESS raises,
    because an emulator ACCEPTING input real AWS refuses must not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


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
