"""create-event-bus-name-collision-different-token-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-event-bus-name-collision-different-token-rejected"
GROUP = "event-bus"
SERVICES = ["eventbridgev2"]

_ACTIVE_TIMEOUT_S = 60.0


def _error_code_and_message(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEventBus for a name already ACTIVE under a different ClientToken is rejected, and
    the original bus survives untouched (not replaced or duplicated).
    """
    ebv2 = ctx.client("eventbridgev2")
    name = ctx.unique_name("sim2real-behav-ebv2-bus-")
    token1 = ctx.unique_name("sim2real-behav-tok1-")
    token2 = ctx.unique_name("sim2real-behav-tok2-")

    first = ebv2.create_event_bus(Name=name, ClientToken=token1)
    bus_arn = first["EventBusArn"]
    ctx.on_cleanup(_teardown_bus(ebv2, bus_arn))
    _wait_active(ebv2, bus_arn)

    code, message = _error_code_and_message(
        lambda: ebv2.create_event_bus(Name=name, ClientToken=token2)
    )
    assert code == "ResourceAlreadyExistsException", (
        f"expected ResourceAlreadyExistsException for a name collision, got {code}: {message!r}"
    )
    assert message == "Resource already exists", f"unexpected message {message!r}"

    survivor = ebv2.describe_event_bus(EventBusArn=bus_arn)
    assert survivor["EventBusArn"] == bus_arn, (
        f"the original bus must survive a rejected collision untouched, got {survivor!r}"
    )
    assert survivor["State"] == "ACTIVE", f"original bus state is {survivor['State']!r}, expected ACTIVE"

    pages = ebv2.get_paginator("list_event_buses").paginate(NamePrefix=name)
    matches = [b["EventBusArn"] for page in pages for b in page["EventBuses"] if b["Name"] == name]
    assert matches == [bus_arn], (
        f"a rejected collision must not add a second bus named {name!r}, found {matches!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
