"""create-event-bus-same-client-token-is-idempotent."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-event-bus-same-client-token-is-idempotent"
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


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Retrying CreateEventBus with the same Name and ClientToken returns the first call's own
    ARN rather than minting a second bus, and ListEventBuses still shows exactly one.
    """
    ebv2 = ctx.client("eventbridgev2")
    name = ctx.unique_name("sim2real-behav-ebv2-bus-")
    token = ctx.unique_name("sim2real-behav-tok-")

    first = ebv2.create_event_bus(Name=name, ClientToken=token)
    bus_arn = first["EventBusArn"]
    ctx.on_cleanup(_teardown_bus(ebv2, bus_arn))
    _wait_active(ebv2, bus_arn)

    retry = ebv2.create_event_bus(Name=name, ClientToken=token)
    assert retry["EventBusArn"] == bus_arn, (
        f"retrying CreateEventBus with the same ClientToken minted a second ARN "
        f"{retry['EventBusArn']!r}, expected the original {bus_arn!r}"
    )

    pages = ebv2.get_paginator("list_event_buses").paginate(NamePrefix=name)
    matches = [b["EventBusArn"] for page in pages for b in page["EventBuses"] if b["Name"] == name]
    assert matches == [bus_arn], (
        f"expected exactly one bus named {name!r} after the idempotent retry, found {matches!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
