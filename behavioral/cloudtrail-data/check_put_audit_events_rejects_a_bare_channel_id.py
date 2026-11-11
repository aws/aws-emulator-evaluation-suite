"""put-audit-events-rejects-a-bare-channel-id."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-audit-events-rejects-a-bare-channel-id"
GROUP = 'audit-event-ingestion'
SERVICES = ['cloudtrail-data']

_BAD_ARN = "The specified channel ARN is not a valid channel ARN."


def _error(fn):
    """(Error.Code, Error.Message) for the ClientError fn() raises. A SUCCESS raises rather than
    returning a falsy sentinel that would read as a mere code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError("the call unexpectedly SUCCEEDED; real AWS rejects it")


def _event() -> dict:
    return {
        "id": str(uuid.uuid4()),
        "eventData": json.dumps(
            {
                "version": "1.0",
                "userIdentity": {"type": "CustomIdentity", "principalId": "sim2real-behav"},
                "eventSource": "sim2real.behavioral",
                "eventName": "Sim2RealProbeEvent",
                "eventTime": "2026-01-01T00:00:00Z",
                "UID": str(uuid.uuid4()),
            }
        ),
    }


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A bare channel id and an ARN naming the wrong service are both refused with InvalidChannelARN and the
    exact invalid-ARN message, while the same id wrapped in a cloudtrail channel ARN gets ChannelNotFound:
    the documented "ARN or ID" form does not accept a bare id.
    """
    ctd = ctx.client("cloudtrail-data")
    account = ctx.client("sts").get_caller_identity()["Account"]
    channel_id = str(uuid.uuid4())
    wrapped = f"arn:aws:cloudtrail:{ctx.region}:{account}:channel/{channel_id}"
    batch = [_event()]

    code, bare_message = _error(
        lambda: ctd.put_audit_events(channelArn=channel_id, auditEvents=batch)
    )
    assert code == "InvalidChannelARN", (
        f"a bare channel id raised {code!r} ({bare_message!r}), expected InvalidChannelARN — the "
        "documented 'ARN or ID' form is not accepted"
    )
    assert bare_message == _BAD_ARN, f"unexpected bare-id message: {bare_message!r}"

    # Positive control: the SAME id, wrapped, gets past ARN parsing and reaches resolution.
    code, arn_form_message = _error(
        lambda: ctd.put_audit_events(channelArn=wrapped, auditEvents=batch)
    )
    assert code == "ChannelNotFound", (
        f"the same id inside a full ARN raised {code!r} ({arn_form_message!r}), expected ChannelNotFound"
    )
    assert arn_form_message == f"The channel {wrapped} could not be found.", (
        f"unexpected resolution message: {arn_form_message!r}"
    )
    assert channel_id in arn_form_message, (
        f"the resolution error does not echo the id it was given: {arn_form_message!r}"
    )

    # A second non-ARN form, to show layer 1 is a real ARN parse and not a length or charset
    # heuristic that a bare uuid happens to trip.
    code, wrong_service_message = _error(
        lambda: ctd.put_audit_events(
            channelArn=f"arn:aws:s3:{ctx.region}:{account}:channel/{channel_id}",
            auditEvents=batch,
        )
    )
    assert code == "InvalidChannelARN", (
        f"an ARN naming the wrong service raised {code!r} ({wrong_service_message!r}), "
        "expected InvalidChannelARN"
    )
    assert wrong_service_message == _BAD_ARN, f"unexpected wrong-service message: {wrong_service_message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
