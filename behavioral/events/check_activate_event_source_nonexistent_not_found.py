"""activate-event-source-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activate-event-source-nonexistent-not-found"
GROUP = "error-semantics"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ActivateEventSource on a never-created partner source returns ResourceNotFoundException,
    stably across two names, and creates nothing; an ordinary bus create/describe is the control."""
    events = ctx.client("events")

    bus_name = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus_name, Tags=[{"Key": "sim2real", "Value": "behavioral"}])
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_event_bus(Name=bus_name)))
    described = events.describe_event_bus(Name=bus_name)
    assert described["Name"] == bus_name, (
        f"positive control failed: expected to describe {bus_name!r}, got {described!r}"
    )

    # Without APN partner registration CreatePartnerEventSource is refused; the source cannot exist.
    bogus = _partner_source_name(ctx)
    err = _error(lambda: events.activate_event_source(Name=bogus))
    expected = _not_found(bogus)
    assert err == expected, (
        f"expected {expected} activating a never-shared partner source, got {err}"
    )

    # repeat with a distinct nonexistent name: the not-found result is stable
    other_bogus = _partner_source_name(ctx)
    err_other = _error(lambda: events.activate_event_source(Name=other_bogus))
    expected_other = _not_found(other_bogus)
    assert err_other == expected_other, (
        f"expected {expected_other} activating a second never-shared partner source, "
        f"got {err_other}"
    )

    # effect absent: the rejected activate call did not conjure a describable source
    describe_err = _error(lambda: events.describe_event_source(Name=bogus))
    expected_describe = ("ResourceNotFoundException", f"Event source {bogus} does not exist.")
    assert describe_err == expected_describe, (
        f"the rejected activate call must not fabricate a describable source, got {describe_err}"
    )


def _not_found(name: str) -> tuple[str, str]:
    """The refusal AWS returns for Activate/DeactivateEventSource on a source never shared here."""
    return (
        "ResourceNotFoundException",
        f"Event source {name} or event bus {name} does not exist.",
    )


def _partner_source_name(ctx) -> str:
    """Build a name matching ^aws\\.partner(/[.\\-_A-Za-z0-9]+){2,}$ -- the pattern EventBridge
    requires for partner event source names."""
    suffix = ctx.unique_name("src-").strip("-")
    return f"aws.partner/sim2real.test/{suffix}"


def _error(fn):
    """Call fn() and return its (code, message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
