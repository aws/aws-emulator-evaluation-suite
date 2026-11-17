"""put-permission-malformed-principal-action-and-statement-id-rejected."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-permission-malformed-principal-action-and-statement-id-rejected"
GROUP = "permission"
SERVICES = ["events"]

_PRINCIPAL = "123456789012"  # AWS documentation example account id


def _error(fn) -> tuple[str, str]:
    """(code, message) of a call that must fail; an unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _policy(events, bus: str) -> dict:
    return json.loads(events.describe_event_bus(Name=bus)["Policy"])


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """PutPermission refuses a Principal, Action or StatementId that does not match its documented
    pattern, leaving the bus policy unchanged, while a correctly formatted grant is stored."""
    events = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    events.put_permission(
        EventBusName=bus, Action="events:PutEvents", Principal=_PRINCIPAL, StatementId="sim2real-ok"
    )
    baseline = _policy(events, bus)
    assert [s["Sid"] for s in baseline["Statement"]] == ["sim2real-ok"], (
        f"positive control: a correctly formatted grant must be stored, policy is {baseline!r}"
    )

    refusals = [
        ("Principal with letters instead of 12 digits",
         lambda: events.put_permission(EventBusName=bus, Action="events:PutEvents",
                                       Principal="1234567890ab", StatementId="sim2real-bad-principal"),
         "principal", "1234567890ab", r"(\d{12}|\*)"),
        ("Action missing the events: prefix",
         lambda: events.put_permission(EventBusName=bus, Action="PutEvents",
                                       Principal=_PRINCIPAL, StatementId="sim2real-bad-action"),
         "action", "PutEvents", r"events:[a-zA-Z]+"),
        ("StatementId carrying a space and an exclamation mark",
         lambda: events.put_permission(EventBusName=bus, Action="events:PutEvents",
                                       Principal=_PRINCIPAL, StatementId="bad id!"),
         "statementId", "bad id!", r"[a-zA-Z0-9-_]+"),
    ]
    for label, call, member, value, pattern in refusals:
        code, message = _error(call)
        expected = (
            "ValidationException",
            f"1 validation error detected: Value '{value}' at '{member}' failed to satisfy "
            f"constraint: Member must satisfy regular expression pattern: {pattern}",
        )
        assert (code, message) == expected, f"{label} must be refused exactly, got {code!r} {message!r}"
        now = _policy(events, bus)
        assert now == baseline, f"{label} was refused but changed the bus policy to {now!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
