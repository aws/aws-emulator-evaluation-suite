"""create-event-bus-reserved-and-malformed-names-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-event-bus-reserved-and-malformed-names-rejected"
GROUP = "event-bus"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEventBus refuses an "aws." name, a name with "/" (partner buses only) and one over 256
    chars, each with its own message and no bus left behind; a well-formed name is accepted."""
    events = ctx.client("events")
    token = ctx.unique_name("sim2real-behav-bus-")

    control = f"{token}-ok"
    events.create_event_bus(Name=control, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=control))
    assert events.describe_event_bus(Name=control)["Name"] == control, "positive control bus was not created"

    too_long = (token + "-" + "x" * 256)[:257]
    cases = [
        (f"aws.{token}", "EventBus name starting with 'aws.' is not valid."),
        (f"{token}/child", "Event bus name must not contain '/'."),
        (too_long, f"1 validation error detected: Value '{too_long}' at 'name' failed to satisfy "
                   "constraint: Member must have length less than or equal to 256"),
    ]
    for name, expected in cases:
        ctx.on_cleanup(lambda n=name: _delete_if_present(events, n))
        code, message = _error(lambda n=name: events.create_event_bus(Name=n))
        assert code == "ValidationException", f"CreateEventBus({name[:60]!r}...) gave {code!r} ({message!r})"
        assert message == expected, f"CreateEventBus({name[:60]!r}...) message {message!r}, expected {expected!r}"

    listed = _list_names(events, token)
    assert listed == [control], (
        f"only the well-formed bus may exist under the run prefix; ListEventBuses returned {listed!r}"
    )
    aws_code, aws_message = _error(lambda: events.describe_event_bus(Name=f"aws.{token}"))
    assert (aws_code, aws_message) == (
        "ValidationException", "EventBus name starting with 'aws.' is not valid."
    ), (
        f"a custom bus in the 'aws.' namespace can never exist, so DescribeEventBus must refuse the "
        f"name the same way; got {aws_code!r} {aws_message!r}"
    )


def _list_names(events, prefix: str) -> list[str]:
    names, token = [], None
    while True:
        kwargs = {"NamePrefix": prefix}
        if token:
            kwargs["NextToken"] = token
        resp = events.list_event_buses(**kwargs)
        names.extend(b["Name"] for b in resp.get("EventBuses", []))
        token = resp.get("NextToken")
        if not token:
            return sorted(names)


def _delete_if_present(events, name: str) -> None:
    """Teardown for a bus that should never exist; deletes it if it was wrongly created."""
    try:
        events.describe_event_bus(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] in ("ResourceNotFoundException", "ValidationException"):
            return
        raise
    events.delete_event_bus(Name=name)


def _error(fn) -> tuple[str, str]:
    """(code, message) of a call that must fail; an unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
