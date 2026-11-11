"""put-audit-events-channel-arn-wrong-service-segment-rejected."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-audit-events-channel-arn-wrong-service-segment-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudtrail-data"]

_BAD_ARN = "The specified channel ARN is not a valid channel ARN."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A channelArn whose service segment is s3 instead of cloudtrail fails InvalidChannelARN,
    while the same shape under cloudtrail is well-formed and fails ChannelNotFound."""
    cloudtrail_data = ctx.client("cloudtrail-data")
    account_id = _account_id(ctx)

    wrong_service_arn = f"arn:aws:s3:{ctx.region}:{account_id}:channel/{uuid.uuid4()}"
    wrong_service_code, wrong_service_message = _error(
        lambda: cloudtrail_data.put_audit_events(
            channelArn=wrong_service_arn,
            auditEvents=[{"id": f"sim2real-{uuid.uuid4().hex}", "eventData": json.dumps(_base_event_data(ctx))}],
        )
    )
    assert wrong_service_code == "InvalidChannelARN", (
        f"expected InvalidChannelARN for a channel ARN naming the wrong AWS service, got {wrong_service_code!r}"
    )
    assert wrong_service_message == _BAD_ARN, f"unexpected malformed-ARN message: {wrong_service_message!r}"

    # Control: the identical resource id under the correct "cloudtrail" service segment
    # is a well-formed-but-nonexistent channel -- ChannelNotFound.
    right_service_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:channel/{uuid.uuid4()}"
    right_service_code, right_service_message = _error(
        lambda: cloudtrail_data.put_audit_events(
            channelArn=right_service_arn,
            auditEvents=[{"id": f"sim2real-{uuid.uuid4().hex}", "eventData": json.dumps(_base_event_data(ctx))}],
        )
    )
    assert right_service_code == "ChannelNotFound", (
        f"expected ChannelNotFound for the correct-service, nonexistent channel, got {right_service_code!r}"
    )
    assert right_service_message == f"The channel {right_service_arn} could not be found.", (
        f"unexpected resolution message: {right_service_message!r}"
    )


def _error(fn):
    """(Error.Code, Error.Message) for the ClientError fn() raises; a success raises."""
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
