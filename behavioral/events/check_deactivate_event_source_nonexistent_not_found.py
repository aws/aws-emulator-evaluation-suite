"""deactivate-event-source-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deactivate-event-source-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeactivateEventSource on a never-shared partner source name is ResourceNotFoundException.

    Repeated with a second name, and the source stays undescribable afterwards.
    """
    events = ctx.client("events")

    # Positive control: a non-partner account cannot create partner sources, so a working bus
    # call proves the not-found below is a targeted existence guard, not a blanket deny.
    bus_name = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus_name)
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus_name))
    described_bus = events.describe_event_bus(Name=bus_name)
    assert described_bus["Name"] == bus_name, (
        f"positive control failed: expected event bus {bus_name!r}, got {described_bus!r}"
    )

    bogus = _partner_source_name(ctx)
    err = _error(lambda: events.deactivate_event_source(Name=bogus))
    expected = _not_found(bogus)
    assert err == expected, (
        f"expected {expected} deactivating a never-shared partner source, got {err}"
    )

    other_bogus = _partner_source_name(ctx)
    err_other = _error(lambda: events.deactivate_event_source(Name=other_bogus))
    expected_other = _not_found(other_bogus)
    assert err_other == expected_other, (
        f"expected {expected_other} deactivating a second never-shared partner source, "
        f"got {err_other}"
    )

    describe_err = _error(lambda: events.describe_event_source(Name=bogus))
    expected_describe = ("ResourceNotFoundException", f"Event source {bogus} does not exist.")
    assert describe_err == expected_describe, (
        f"the rejected deactivate call must not fabricate a describable source, got {describe_err}"
    )


def _not_found(name: str) -> tuple[str, str]:
    """The refusal AWS returns for Activate/DeactivateEventSource on a source never shared here."""
    return (
        "ResourceNotFoundException",
        f"Event source {name} or event bus {name} does not exist.",
    )


def _partner_source_name(ctx) -> str:
    """A name matching the pattern EventBridge requires for partner event source names."""
    suffix = ctx.unique_name("src-").strip("-")
    return f"aws.partner/sim2real.test/{suffix}"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
