"""list-event-buses-limit-above-the-documented-maximum-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-event-buses-limit-above-the-documented-maximum-rejected"
GROUP = "event-bus"
SERVICES = ["events"]


def _error(fn) -> tuple[str, str]:
    """(code, message) of a call that must fail; an unexpected success raises, naming the result."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListEventBuses refuses a Limit one past its documented maximum of 100, while the maximum
    itself still returns the bus a prefix search names."""
    events = ctx.client("events")
    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: events.delete_event_bus(Name=bus))

    code, message = _error(lambda: events.list_event_buses(Limit=101))
    assert (code, message) == (
        "ValidationException",
        "1 validation error detected: Value '101' at 'limit' failed to satisfy constraint: "
        "Member must have value less than or equal to 100",
    ), f"Limit=101 must be refused exactly, got {code!r} {message!r}"

    found = events.list_event_buses(NamePrefix=bus, Limit=100)["EventBuses"]
    names = [b["Name"] for b in found]
    assert names == [bus], f"the documented maximum Limit must still list the bus, got {names!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
