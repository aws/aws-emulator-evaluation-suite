"""put-audit-events-batch-exceeds-max-size-rejected."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-audit-events-batch-exceeds-max-size-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudtrail-data"]

_OVER_MAX = 101  # documented AuditEvents list max length is 100


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A 101-event PutAuditEvents batch fails with the length ValidationException, while a
    100-event batch to the same absent channel clears the constraint and fails ChannelNotFound,
    pinning the inclusive ceiling at exactly 100."""
    cloudtrail_data = ctx.client("cloudtrail-data")
    account_id = _account_id(ctx)
    channel_arn = f"arn:aws:cloudtrail:{ctx.region}:{account_id}:channel/{uuid.uuid4()}"

    def _events(n: int) -> list[dict]:
        return [
            {"id": f"sim2real-{uuid.uuid4().hex}", "eventData": json.dumps(_base_event_data(ctx))}
            for _ in range(n)
        ]

    try:
        cloudtrail_data.put_audit_events(channelArn=channel_arn, auditEvents=_events(100))
        raise AssertionError(
            "a 100-event batch against a nonexistent channel unexpectedly SUCCEEDED"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ChannelNotFound", (
            f"a 100-event batch raised {code!r}, expected ChannelNotFound -- the batch "
            "ceiling is not inclusive at 100"
        )
        message = exc.response["Error"].get("Message", "")
        assert message == f"The channel {channel_arn} could not be found.", (
            f"unexpected resolution message for a 100-event batch: {message!r}"
        )

    over_max = _events(_OVER_MAX)
    try:
        resp = cloudtrail_data.put_audit_events(
            channelArn=channel_arn, auditEvents=over_max
        )
        raise AssertionError(
            f"expected rejection of a {_OVER_MAX}-event batch (max is 100), got "
            f"{len(resp.get('successful', []))} successful / {len(resp.get('failed', []))} failed"
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "ValidationException", (
            f"unexpected server-side error code for an oversized batch: {code!r}"
        )
        message = exc.response["Error"].get("Message", "")
        assert message == (
            f"1 validation error detected: Value '{_java_list(over_max)}' at 'auditEvents' "
            "failed to satisfy constraint: Member must have length less than or equal to 100"
        ), f"unexpected over-size violation message: {message[:300]!r}"


def _java_list(events: list[dict]) -> str:
    """The service echoes the rejected list in its Java toString form."""
    return "[" + ", ".join(
        f"AuditEvent(id={e['id']}, eventData={e['eventData']}, eventDataChecksum=null)"
        for e in events
    ) + "]"


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
