"""activate-deactivate-event-source-state-transition."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activate-deactivate-event-source-state-transition"
GROUP = "state-machine"
SERVICES = ["events"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Activate/Deactivate/DescribeEventSource reject a partner source never shared to this account
    with ResourceNotFoundException and its exact message, and never fabricate a describable source.
    Only a real SaaS partner can share a source, so the PENDING/ACTIVE transition is unreachable."""
    events = ctx.client("events")

    partner_segment = ctx.unique_name("sim2real-behav-partner-")
    source_name = f"aws.partner/{partner_segment}/testnamespace/testevent"

    not_described = (
        "ResourceNotFoundException",
        f"Event source {source_name} does not exist.",
    )
    not_found = (
        "ResourceNotFoundException",
        f"Event source {source_name} or event bus {source_name} does not exist.",
    )

    describe_err = _error(lambda: events.describe_event_source(Name=source_name))
    assert describe_err == not_described, (
        f"expected {not_described} describing an unshared source, got {describe_err}"
    )

    activate_err = _error(lambda: events.activate_event_source(Name=source_name))
    assert activate_err == not_found, (
        f"expected {not_found} activating an unshared source, got {activate_err}"
    )

    describe_after_activate_err = _error(lambda: events.describe_event_source(Name=source_name))
    assert describe_after_activate_err == not_described, (
        f"activate must not have created a describable source, got {describe_after_activate_err}"
    )

    deactivate_err = _error(lambda: events.deactivate_event_source(Name=source_name))
    assert deactivate_err == not_found, (
        f"expected {not_found} deactivating an unshared source, got {deactivate_err}"
    )

    describe_after_deactivate_err = _error(lambda: events.describe_event_source(Name=source_name))
    assert describe_after_deactivate_err == not_described, (
        f"deactivate must not have created a describable source, got {describe_after_deactivate_err}"
    )

    # Positive control: an ordinary bus works with the same credentials, so the errors above are
    # a targeted existence guard rather than a blanket deny.
    bus_name = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus_name)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: events.delete_event_bus(Name=bus_name)))
    described = events.describe_event_bus(Name=bus_name)
    assert described["Name"] == bus_name, (
        f"expected the positive-control event bus {bus_name!r} to describe back its own name, "
        f"got {described.get('Name')!r}"
    )


def _error(fn):
    """Call fn() and return its (code, message); an unexpected success raises, so an accepted
    call is reported as such rather than as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as err:
        if err.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
