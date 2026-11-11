"""event-bus-create-describe-list-delete-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-bus-create-describe-list-delete-lifecycle"
GROUP = "event-bus"
SERVICES = ["eventbridgev2"]

_ACTIVE_TIMEOUT_S = 60.0


def _teardown_bus(ebv2, bus_arn: str):
    """Delete the bus, waiting out a transient CREATING/DELETING rather than hiding it."""

    def run_undo() -> None:
        deadline = time.monotonic() + _ACTIVE_TIMEOUT_S
        while True:
            try:
                ebv2.delete_event_bus(EventBusArn=bus_arn)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "ResourceNotFoundException":
                    return
                if code != "InvalidStateException" or time.monotonic() > deadline:
                    raise
                time.sleep(2)

    return run_undo


def _wait_active(ebv2, bus_arn: str) -> dict:
    deadline = time.monotonic() + _ACTIVE_TIMEOUT_S
    while True:
        described = ebv2.describe_event_bus(EventBusArn=bus_arn)
        if described["State"] == "ACTIVE":
            return described
        if time.monotonic() > deadline:
            raise AssertionError(f"bus stayed {described['State']!r}, never reached ACTIVE")
        time.sleep(2)


def _wait_gone(ebv2, bus_arn: str) -> None:
    deadline = time.monotonic() + _ACTIVE_TIMEOUT_S
    while True:
        try:
            described = ebv2.describe_event_bus(EventBusArn=bus_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() > deadline:
            raise AssertionError(f"bus stayed {described['State']!r}, never disappeared")
        time.sleep(2)


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEventBus starts CREATING and settles to ACTIVE; DescribeEventBus and ListEventBuses
    agree on its fields, and DeleteEventBus removes it for both reads.
    """
    ebv2 = ctx.client("eventbridgev2")
    name = ctx.unique_name("sim2real-behav-ebv2-bus-")

    created = ebv2.create_event_bus(Name=name, ClientToken=ctx.unique_name("sim2real-behav-tok-"))
    bus_arn = created["EventBusArn"]
    ctx.on_cleanup(_teardown_bus(ebv2, bus_arn))
    assert created["State"] in ("CREATING", "ACTIVE"), (
        f"CreateEventBus returned state {created['State']!r}, expected CREATING or ACTIVE"
    )

    described = _wait_active(ebv2, bus_arn)
    assert described["Name"] == name, f"expected Name {name!r}, got {described['Name']!r}"
    assert described["EventBusArn"] == bus_arn, (
        f"DescribeEventBus ARN {described['EventBusArn']!r} != CreateEventBus ARN {bus_arn!r}"
    )

    pages = ebv2.get_paginator("list_event_buses").paginate(NamePrefix=name)
    matches = [b for page in pages for b in page["EventBuses"] if b["Name"] == name]
    assert len(matches) == 1, f"expected exactly one bus named {name!r} in the list, got {matches!r}"
    assert matches[0]["EventBusArn"] == bus_arn, (
        f"listed ARN {matches[0]['EventBusArn']!r} != created ARN {bus_arn!r}"
    )
    assert matches[0]["State"] == "ACTIVE", f"listed state {matches[0]['State']!r}, expected ACTIVE"

    ebv2.delete_event_bus(EventBusArn=bus_arn)
    _wait_gone(ebv2, bus_arn)

    pages = ebv2.get_paginator("list_event_buses").paginate(NamePrefix=name)
    remaining = [b for page in pages for b in page["EventBuses"] if b["Name"] == name]
    assert remaining == [], f"deleted bus {name!r} still appears in ListEventBuses: {remaining!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
