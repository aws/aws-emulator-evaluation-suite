"""delete-event-bus-blocked-by-event-source-until-revoked."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-event-bus-blocked-by-event-source-until-revoked"
GROUP = "event-bus-delete"
SERVICES = ["eventbridgev2"]

_SETTLE_TIMEOUT_S = 60.0
_DELETE_TIMEOUT_S = 120.0


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _refused(fn, on_success=None):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises.

    An unexpected success hands its result to ``on_success`` (to register its cleanup) and fails.
    """
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    if on_success is not None:
        on_success(result)
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _bus_teardown(ebv2, bus_arn: str):
    """Delete the bus, waiting out a transient state or a child whose delete is still settling."""

    def run_undo() -> None:
        deadline = time.monotonic() + _SETTLE_TIMEOUT_S
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


def _wait_bus_state(ctx, ebv2, bus_arn: str, state: str) -> dict:
    """DescribeEventBus once the bus reports ``state``."""
    deadline = time.monotonic() + _budget_s(ctx, _SETTLE_TIMEOUT_S)
    while True:
        described = ebv2.describe_event_bus(EventBusArn=bus_arn)
        if described["State"] == state:
            return described
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError("the run budget ended before the bus settled; not graded")
            raise AssertionError(f"bus stayed {described['State']!r}, never reached {state}")
        time.sleep(2)


def _create_bus(ctx, ebv2, **kwargs) -> dict:
    """An ACTIVE bus of the check's own, deleted at cleanup."""
    bus = ebv2.create_event_bus(
        Name=kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-ebv2-bus-"),
        ClientToken=ctx.unique_name("sim2real-behav-tok-"),
        **kwargs,
    )
    ctx.on_cleanup(_bus_teardown(ebv2, bus["EventBusArn"]))
    _wait_bus_state(ctx, ebv2, bus["EventBusArn"], "ACTIVE")
    return bus


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteEventBus is refused while an event source on the bus is not revoked and succeeds once
    it is revoked; the revoked source outlives the bus and is still deletable.
    
    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-custom-bus-create.html
    """
    ebv2 = ctx.client("eventbridgev2")
    bus_arn = _create_bus(ctx, ebv2)["EventBusArn"]
    created = ebv2.create_event_source(
        Name=ctx.unique_name("sim2real-behav-ebv2-src-"), EventBusArn=bus_arn,
        ClientToken=ctx.unique_name("sim2real-behav-stok-"),
        Configuration={"AwsServiceEventsConfiguration": {"AwsService": "aws.ec2"}})
    source_arn = created["EventSourceArn"]
    ctx.on_cleanup(_teardown(lambda: ebv2.delete_event_source(EventSourceArn=source_arn),
                             "ResourceNotFoundException"))

    got = _refused(lambda: ebv2.delete_event_bus(EventBusArn=bus_arn))
    assert got == ("ResourceInUseException",
                   "The event bus cannot be deleted because it has one or more event sources that are "
                   "not revoked. Delete or revoke them and retry."), (
        f"DeleteEventBus with a live event source answered {got!r}"
    )
    assert ebv2.describe_event_bus(EventBusArn=bus_arn)["State"] == "ACTIVE", (
        "a refused DeleteEventBus changed the bus state"
    )

    ebv2.revoke_resource(Arn=source_arn)
    ebv2.delete_event_bus(EventBusArn=bus_arn)
    deadline = time.monotonic() + _budget_s(ctx, _DELETE_TIMEOUT_S)
    while True:
        try:
            state = ebv2.describe_event_bus(EventBusArn=bus_arn)["State"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            break
        if time.monotonic() > deadline:
            if _budget_spent(ctx):
                raise TimeoutError("the run budget ended before the bus was deleted; not graded")
            raise AssertionError(f"bus stayed {state!r} after DeleteEventBus")
        time.sleep(2)

    orphan = ebv2.describe_event_source(EventSourceArn=source_arn)
    assert orphan.get("Revoked") is True and orphan["EventBusArn"] == bus_arn, (
        f"the revoked source after its bus was deleted describes as {orphan!r}"
    )
    ebv2.delete_event_source(EventSourceArn=source_arn)
    got = _refused(lambda: ebv2.describe_event_source(EventSourceArn=source_arn))
    assert got == ("ResourceNotFoundException", f"EventSource not found: {source_arn}"), (
        f"the deleted source describes as {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
