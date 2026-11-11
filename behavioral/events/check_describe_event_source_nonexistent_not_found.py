"""describe-event-source-nonexistent-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-event-source-nonexistent-not-found"
GROUP = 'event-source'
SERVICES = ['events']

def _error(fn):
    """(code, message) of a call that must fail; a call that succeeds raises AssertionError."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded with {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeEventSource for a never-created partner event source fails with
    ResourceNotFoundException and ListEventSources does not list it; an ordinary event bus
    is a positive control showing the client and credentials are otherwise healthy."""
    ev = ctx.client("events")

    bus_name = ctx.unique_name("sim2real-behav-bus-")
    ev.create_event_bus(Name=bus_name)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: ev.delete_event_bus(Name=bus_name)))
    described_bus = ev.describe_event_bus(Name=bus_name)
    assert described_bus["Name"] == bus_name, f"expected {bus_name}, got {described_bus.get('Name')}"

    bogus = "aws.partner/example.com/" + ctx.unique_name("src-")

    err = _error(lambda: ev.describe_event_source(Name=bogus))
    assert err == ("ResourceNotFoundException", f"Event source {bogus} does not exist."), (
        f"expected ResourceNotFoundException, got {err!r}"
    )

    listed = ev.list_event_sources(NamePrefix=bogus)["EventSources"]
    assert listed == [], f"unknown partner event source must not be listed: {listed}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
