"""delete-event-bus-blocked-while-a-rule-remains-and-succeeds-once-removed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-event-bus-blocked-while-a-rule-remains-and-succeeds-once-removed"
GROUP = "event-bus"
SERVICES = ["events"]

_EXPECTED_BLOCK_CODE = "ValidationException"
_BUS_GONE_TIMEOUT_S = 60.0


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteEventBus on a custom bus with a plain rule attached is a 400 ValidationException that
    leaves bus and rule intact; the identical call succeeds once the rule is removed.
    """
    events = ctx.client("events")

    # Positive control: DeleteEventBus works on an undecorated bus.
    control_bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=control_bus, Tags=[{"Key": "sim2real:managed", "Value": "true"}])
    ctx.on_cleanup(lambda n=control_bus: _delete_bus_quietly(events, n))
    events.delete_event_bus(Name=control_bus)
    control_gone = _poll_until(
        lambda: _is_not_found(lambda: events.describe_event_bus(Name=control_bus)),
        lambda gone: gone,
        timeout_s=_BUS_GONE_TIMEOUT_S,
    )
    assert control_gone, (
        f"positive control failed: after DeleteEventBus({control_bus}) DescribeEventBus must "
        f"eventually return ResourceNotFoundException -- DeleteEventBus is not working in this "
        f"account/region, so the refusal asserted below would prove nothing"
    )

    bus = ctx.unique_name("sim2real-behav-bus-")
    events.create_event_bus(Name=bus, Tags=[{"Key": "sim2real:managed", "Value": "true"}])
    ctx.on_cleanup(lambda n=bus: _delete_bus_quietly(events, n))

    rule = ctx.unique_name("sim2real-behav-rule-")
    events.put_rule(
        Name=rule,
        EventBusName=bus,
        EventPattern=json.dumps({"source": ["sim2real.deleteblock"]}),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda n=rule, b=bus: _delete_rule_quietly(events, n, b))

    code, message, status = _error(lambda: events.delete_event_bus(Name=bus))
    assert code == _EXPECTED_BLOCK_CODE, (
        f"expected the rule dependency refusal to be {_EXPECTED_BLOCK_CODE!r}, got {code!r} with "
        f"message {message!r}"
    )
    assert status == 400, f"the rule dependency refusal carried HTTP {status!r}, expected 400"
    expected_message = "EventBus can't be deleted since it has rules."
    assert message == expected_message, (
        f"expected the refusal message {expected_message!r}, got {message!r}"
    )

    still_there = events.describe_event_bus(Name=bus)
    assert still_there["Name"] == bus, (
        f"the refused delete must leave the bus describable, got {still_there!r}"
    )
    rule_after = events.describe_rule(Name=rule, EventBusName=bus)
    assert rule_after["Name"] == rule, (
        f"the refused delete must leave the rule describable, got {rule_after!r}"
    )
    listed = [b["Name"] for b in events.list_event_buses(NamePrefix=bus)["EventBuses"]]
    assert bus in listed, f"the refused delete must leave {bus!r} in ListEventBuses, got {listed}"

    events.delete_rule(Name=rule, EventBusName=bus, Force=True)
    rule_gone = _poll_until(
        lambda: _is_not_found(lambda: events.describe_rule(Name=rule, EventBusName=bus)),
        lambda gone: gone,
        timeout_s=_BUS_GONE_TIMEOUT_S,
    )
    assert rule_gone, (
        f"DescribeRule({rule}) must eventually return ResourceNotFoundException once the rule is "
        f"deleted"
    )

    events.delete_event_bus(Name=bus)
    final_gone = _poll_until(
        lambda: _is_not_found(lambda: events.describe_event_bus(Name=bus)),
        lambda gone: gone,
        timeout_s=_BUS_GONE_TIMEOUT_S,
    )
    assert final_gone, (
        f"once its rule was removed, the identical DeleteEventBus({bus}) must succeed and leave "
        f"DescribeEventBus eventually returning ResourceNotFoundException"
    )
    final_listed = [b["Name"] for b in events.list_event_buses(NamePrefix=bus)["EventBuses"]]
    assert final_listed == [], (
        f"the deleted bus must be absent from ListEventBuses(NamePrefix={bus!r}), got {final_listed}"
    )


def _error(fn) -> tuple[str, str, int | None]:
    """(error code, message, HTTP status) for a call expected to fail; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return (err.get("Code"), err.get("Message") or "",
                exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode"))
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _is_not_found(fn) -> bool:
    """A poll probe: True once fn() raises ResourceNotFoundException, False while it still
    succeeds or raises anything else."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException"
    return False


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s. Last result: {last!r}")


def _delete_rule_quietly(events, name: str, bus: str) -> None:
    try:
        events.delete_rule(Name=name, EventBusName=bus, Force=True)
    except events.exceptions.ResourceNotFoundException:
        pass
    except ClientError as exc:
        raise AssertionError(
            f"could not delete rule {name}: {exc.response['Error']['Code']}"
        ) from exc


def _delete_bus_quietly(events, name: str) -> None:
    try:
        events.delete_event_bus(Name=name)
    except events.exceptions.ResourceNotFoundException:
        pass
    except ClientError as exc:
        raise AssertionError(
            f"could not delete event bus {name}: {exc.response['Error']['Code']}"
        ) from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
