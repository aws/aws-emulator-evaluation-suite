"""delete-event-bus-with-subscriber-rejected-until-removed."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-event-bus-with-subscriber-rejected-until-removed"
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
                if code not in ("InvalidStateException", "ResourceInUseException"):
                    raise
                if time.monotonic() > deadline:
                    raise
                time.sleep(2)

    return run_undo


def _wait_bus_active(ebv2, bus_arn: str) -> None:
    deadline = time.monotonic() + _ACTIVE_TIMEOUT_S
    while True:
        described = ebv2.describe_event_bus(EventBusArn=bus_arn)
        if described["State"] == "ACTIVE":
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"bus stayed {described['State']!r}, never reached ACTIVE")
        time.sleep(2)


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteEventBus refuses while a subscriber still exists on it, and succeeds once that
    subscriber is removed -- proving the block is scoped to the subscriber, not to the bus.
    """
    ebv2 = ctx.client("eventbridgev2")
    bus_name = ctx.unique_name("sim2real-behav-ebv2-bus-")
    sub_name = ctx.unique_name("sim2real-behav-ebv2-sub-")

    bus = ebv2.create_event_bus(Name=bus_name, ClientToken=ctx.unique_name("sim2real-behav-tok-"))
    bus_arn = bus["EventBusArn"]
    ctx.on_cleanup(_teardown_bus(ebv2, bus_arn))
    _wait_bus_active(ebv2, bus_arn)

    sub = ebv2.create_subscriber(
        Name=sub_name,
        EventBusArn=bus_arn,
        ClientToken=ctx.unique_name("sim2real-behav-stok-"),
        InvokeConfiguration={
            "RoleArn": f"arn:aws:iam::{ctx.account}:role/sim2real-behav-ebv2-unused-role",
            "TargetArn": f"arn:aws:sqs:{ctx.region}:{ctx.account}:sim2real-behav-ebv2-unused-q",
        },
    )
    sub_arn = sub["SubscriberArn"]
    sub_deleted = False

    def _delete_sub_if_needed() -> None:
        if not sub_deleted:
            _ignore_not_found(lambda: ebv2.delete_subscriber(SubscriberArn=sub_arn))

    ctx.on_cleanup(_delete_sub_if_needed)

    code, message = _error_code_and_message(lambda: ebv2.delete_event_bus(EventBusArn=bus_arn))
    assert code == "ResourceInUseException", (
        f"expected ResourceInUseException while a subscriber exists, got {code}: {message!r}"
    )
    assert message == (
        "The event bus cannot be deleted because it has one or more subscribers that are not "
        "revoked. Delete or revoke them and retry."
    ), f"unexpected message {message!r}"

    survivor = ebv2.describe_event_bus(EventBusArn=bus_arn)
    assert survivor["State"] == "ACTIVE", (
        f"a rejected delete must leave the bus ACTIVE, got {survivor['State']!r}"
    )

    ebv2.delete_subscriber(SubscriberArn=sub_arn)
    sub_deleted = True
    ebv2.delete_event_bus(EventBusArn=bus_arn)


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
