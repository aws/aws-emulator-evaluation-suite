"""put-audit-events-rejects-a-batch-over-one-hundred-events."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-audit-events-rejects-a-batch-over-one-hundred-events"
GROUP = 'audit-event-ingestion'
SERVICES = ['cloudtrail-data']


def _error(fn):
    """(Error.Code, Error.Message) for the ClientError fn() raises; a success raises."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError("the call unexpectedly SUCCEEDED; real AWS rejects it")


def _java_list(events: list[dict]) -> str:
    """The service echoes the rejected list in its Java toString form."""
    return "[" + ", ".join(
        f"AuditEvent(id={e['id']}, eventData={e['eventData']}, eventDataChecksum=null)"
        for e in events
    ) + "]"


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
    """The batch ceiling is inclusive at 100 and the per-id ceiling inclusive at 128: at each
    limit the call reaches channel resolution (ChannelNotFound), one over fails validation, and
    two violations in one batch are reported together with 1-based member paths."""
    ctd = ctx.client("cloudtrail-data")
    account = ctx.client("sts").get_caller_identity()["Account"]
    absent = f"arn:aws:cloudtrail:{ctx.region}:{account}:channel/{uuid.uuid4()}"
    not_found = f"The channel {absent} could not be found."

    # Positive control for the batch bound: exactly 100 events clears the constraint layer, and
    # reaching channel resolution is the only observable proof that it did.
    code, at_limit = _error(
        lambda: ctd.put_audit_events(
            channelArn=absent, auditEvents=[_event() for _ in range(100)]
        )
    )
    assert code == "ChannelNotFound", (
        f"a 100-event batch raised {code!r} ({at_limit!r}); the batch ceiling is not "
        "inclusive at 100"
    )
    assert at_limit == not_found, f"unexpected resolution message at 100 events: {at_limit!r}"

    over_batch = [_event() for _ in range(101)]
    code, over_limit = _error(
        lambda: ctd.put_audit_events(channelArn=absent, auditEvents=over_batch)
    )
    assert code == "ValidationException", (
        f"a 101-event batch raised {code!r}, expected ValidationException — "
        f"message began {over_limit[:200]!r}"
    )
    assert over_limit == (
        f"1 validation error detected: Value '{_java_list(over_batch)}' at 'auditEvents' "
        "failed to satisfy constraint: Member must have length less than or equal to 100"
    ), f"unexpected over-size violation message: {over_limit[:300]!r}"

    # Positive control for the id bound: 128 characters is the longest legal id.
    code, id_at_limit = _error(
        lambda: ctd.put_audit_events(channelArn=absent, auditEvents=[_event("a" * 128)])
    )
    assert code == "ChannelNotFound", (
        f"a 128-character event id raised {code!r} ({id_at_limit!r}); the id ceiling is not "
        "inclusive at 128"
    )
    assert id_at_limit == not_found, f"unexpected resolution message at id=128: {id_at_limit!r}"

    code, id_over = _error(
        lambda: ctd.put_audit_events(channelArn=absent, auditEvents=[_event("a" * 129)])
    )
    assert code == "ValidationException", (
        f"a 129-character event id raised {code!r} ({id_over!r}), expected ValidationException"
    )
    assert id_over == (
        "1 validation error detected: Value '" + "a" * 129 + "' at 'auditEvents.1.member.id' "
        "failed to satisfy constraint: Member must have length less than or equal to 128"
    ), f"unexpected id-length violation message: {id_over!r}"

    # Two violations in one batch are reported together, and the member paths are 1-based.
    code, both = _error(
        lambda: ctd.put_audit_events(
            channelArn=absent, auditEvents=[_event("sim2real bad id!"), _event("a" * 129)]
        )
    )
    assert code == "ValidationException", (
        f"a batch with two constraint violations raised {code!r} ({both[:200]!r}), "
        "expected ValidationException"
    )
    assert both == (
        "2 validation errors detected: Value 'sim2real bad id!' at 'auditEvents.1.member.id' "
        "failed to satisfy constraint: Member must satisfy regular expression pattern: "
        "[-_A-Za-z0-9]+; Value '" + "a" * 129 + "' at 'auditEvents.2.member.id' failed to "
        "satisfy constraint: Member must have length less than or equal to 128"
    ), f"the two violations were not reported in aggregate with 1-based paths: {both!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
