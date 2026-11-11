"""put-audit-events-rejects-in-arn-then-constraint-then-channel-order."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-audit-events-rejects-in-arn-then-constraint-then-channel-order"
GROUP = 'audit-event-ingestion'
SERVICES = ['cloudtrail-data']

_BAD_ARN = "The specified channel ARN is not a valid channel ARN."


def _error(fn):
    """(Error.Code, Error.Message) for the ClientError fn() raises. A SUCCESS raises rather than
    returning a falsy sentinel: an emulator that ACCEPTS a batch real AWS refuses is the
    strongest signal here, and must not read as a code mismatch."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError("the call unexpectedly SUCCEEDED; real AWS rejects it")


def _event(event_id: str | None = None) -> dict:
    return {
        "id": event_id or str(uuid.uuid4()),
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
    """PutAuditEvents rejects in a fixed order: a malformed ARN (InvalidChannelARN, same message with a valid
    or invalid batch) masks an invalid id pattern (ValidationException, exact message), which masks a
    missing channel (ChannelNotFound, exact message).
    """
    ctd = ctx.client("cloudtrail-data")
    # The account segment has to be this account's: a channel ARN in any other account is an
    # authorization failure long before it is a resolution failure, which would silently swap
    # layer 3 for a 403 and make the ordering claim untestable.
    account = ctx.client("sts").get_caller_identity()["Account"]
    absent = f"arn:aws:cloudtrail:{ctx.region}:{account}:channel/{uuid.uuid4()}"
    good_batch = [_event()]
    bad_batch = [_event("sim2real bad id!")]

    # Layer 1 wins over layer 2: the payload violates the modelled `id` pattern AND the ARN is
    # not an ARN, and it is the ARN that is reported.
    code, both_broken = _error(
        lambda: ctd.put_audit_events(channelArn="sim2real-not-an-arn", auditEvents=bad_batch)
    )
    assert code == "InvalidChannelARN", (
        f"a malformed ARN with an invalid batch raised {code!r} ({both_broken!r}), "
        "expected InvalidChannelARN"
    )
    assert both_broken == _BAD_ARN, f"unexpected malformed-ARN message: {both_broken!r}"

    # Fix only the ARN: the same batch is now rejected by the constraint layer, which proves the
    # violation was there all along and was merely masked.
    code, constraint = _error(
        lambda: ctd.put_audit_events(channelArn=absent, auditEvents=bad_batch)
    )
    assert code == "ValidationException", (
        f"a well-formed ARN with an invalid batch raised {code!r} ({constraint!r}), "
        "expected ValidationException"
    )
    assert constraint == (
        "1 validation error detected: Value 'sim2real bad id!' at 'auditEvents.1.member.id' "
        "failed to satisfy constraint: Member must satisfy regular expression pattern: "
        "[-_A-Za-z0-9]+"
    ), f"unexpected constraint-violation message: {constraint!r}"

    # Layer 2 wins over layer 3, shown by fixing only the batch: the channel was never resolvable,
    # and only now is that what comes back.
    code, not_found = _error(
        lambda: ctd.put_audit_events(channelArn=absent, auditEvents=good_batch)
    )
    assert code == "ChannelNotFound", (
        f"a well-formed absent ARN with a valid batch raised {code!r} ({not_found!r}), "
        "expected ChannelNotFound"
    )
    assert not_found == f"The channel {absent} could not be found.", (
        f"unexpected channel-resolution message: {not_found!r}"
    )

    # Positive control on the layer under test: the SAME valid batch that reached layer 3 above
    # is still refused at layer 1 by a malformed ARN, so the batch is not what any of these
    # rejections is about.
    code, arn_again = _error(
        lambda: ctd.put_audit_events(channelArn="sim2real-not-an-arn", auditEvents=good_batch)
    )
    assert code == "InvalidChannelARN", (
        f"a malformed ARN with a VALID batch raised {code!r} ({arn_again!r}), "
        "expected InvalidChannelARN"
    )
    assert arn_again == both_broken, (
        "the malformed-ARN message depends on the payload, so layer 1 is not payload-independent: "
        f"{arn_again!r} vs {both_broken!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
