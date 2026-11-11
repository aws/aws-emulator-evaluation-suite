"""create-duplicate-event-bus-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-duplicate-event-bus-fails"
GROUP = 'event-bus'
SERVICES = ['events']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEventBus with a Name that already belongs to an existing bus is rejected with
    ResourceAlreadyExistsException instead of silently succeeding or overwriting the original
    bus's configuration, and CreateEventBus still works for a genuinely fresh name."""
    ev = ctx.client("events")
    name = ctx.unique_name("sim2real-behav-bus-")
    ev.create_event_bus(Name=name, Description="original")
    ctx.on_cleanup(lambda n=name: ev.delete_event_bus(Name=n))

    err = _error(
        lambda: ev.create_event_bus(Name=name, Description="duplicate-attempt")
    )
    expected = ("ResourceAlreadyExistsException", f"Event bus {name} already exists.")
    assert err == expected, (
        f"expected duplicate CreateEventBus to fail with {expected}, got {err}"
    )

    # Effect absent: the original bus's Description was NOT overwritten by the rejected
    # duplicate-name create call.
    described = ev.describe_event_bus(Name=name)
    assert described["Description"] == "original", (
        f"duplicate CreateEventBus must not mutate the existing bus, got Description="
        f"{described['Description']!r}"
    )

    # Positive control: CreateEventBus with a genuinely different Name still succeeds --
    # proving CreateEventBus works in general, and the rejection above is specifically about
    # the name collision.
    other_name = ctx.unique_name("sim2real-behav-bus2-")
    other = ev.create_event_bus(Name=other_name, Description="other")
    ctx.on_cleanup(lambda n=other_name: ev.delete_event_bus(Name=n))
    assert other_name in other["EventBusArn"], (
        f"expected control CreateEventBus to succeed with an ARN naming {other_name!r}, "
        f"got {other['EventBusArn']!r}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
