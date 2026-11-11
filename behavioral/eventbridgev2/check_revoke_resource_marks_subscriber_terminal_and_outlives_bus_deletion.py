"""revoke-resource-marks-subscriber-terminal-and-outlives-bus-deletion."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "revoke-resource-marks-subscriber-terminal-and-outlives-bus-deletion"
GROUP = "subscriber-revocation"
SERVICES = ["eventbridgev2"]

_ACTIVE_TIMEOUT_S = 60.0
_DELETE_TIMEOUT_S = 120.0
_REVOKED_UPDATE = ("InvalidStateException", "Subscriber is revoked and cannot be updated")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

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


def _wait_bus_gone(ebv2, bus_arn: str) -> None:
    deadline = time.monotonic() + _DELETE_TIMEOUT_S
    while True:
        try:
            described = ebv2.describe_event_bus(EventBusArn=bus_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() > deadline:
            raise AssertionError(f"bus stayed {described['State']!r} and never disappeared")
        time.sleep(2)


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {(code, message)!r}, but the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RevokeResource marks a subscriber Revoked and terminal: UpdateSubscriber on it is then
    refused with InvalidStateException, while DeleteEventBus still succeeds with it present.

    Reference: https://docs.aws.amazon.com/eventbridgev2/latest/APIReference/API_RevokeResource.html
    """
    ebv2 = ctx.client("eventbridgev2")
    bus_name = ctx.unique_name("sim2real-behav-ebv2-bus-")
    sub_name = ctx.unique_name("sim2real-behav-ebv2-sub-")

    bus = ebv2.create_event_bus(Name=bus_name, ClientToken=ctx.unique_name("sim2real-behav-tok-"))
    bus_arn = bus["EventBusArn"]
    ctx.on_cleanup(_teardown(lambda: ebv2.delete_event_bus(EventBusArn=bus_arn),
                             "ResourceNotFoundException"))
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
    ctx.on_cleanup(_teardown(lambda: ebv2.delete_subscriber(SubscriberArn=sub_arn),
                             "ResourceNotFoundException"))

    fresh = ebv2.describe_subscriber(SubscriberArn=sub_arn)
    assert "Revoked" not in fresh, f"a fresh subscriber must not report Revoked, got {fresh!r}"

    ebv2.revoke_resource(Arn=sub_arn)

    revoked = ebv2.describe_subscriber(SubscriberArn=sub_arn)
    assert revoked.get("Revoked") is True, (
        f"after RevokeResource, DescribeSubscriber's Revoked was {revoked.get('Revoked')!r}"
    )

    expect_error(
        lambda: ebv2.update_subscriber(SubscriberArn=sub_arn, Description="sim2real-behav-ebv2-blocked"),
        *_REVOKED_UPDATE,
    )

    ebv2.delete_event_bus(EventBusArn=bus_arn)
    _wait_bus_gone(ebv2, bus_arn)

    still_there = ebv2.describe_subscriber(SubscriberArn=sub_arn)
    assert still_there["SubscriberArn"] == sub_arn, (
        f"the revoked subscriber must survive its bus's deletion, describe gave {still_there!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
