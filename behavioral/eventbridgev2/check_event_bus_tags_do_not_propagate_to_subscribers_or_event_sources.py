"""event-bus-tags-do-not-propagate-to-subscribers-or-event-sources."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-bus-tags-do-not-propagate-to-subscribers-or-event-sources"
GROUP = "tagging"
SERVICES = ["eventbridgev2"]

_SETTLE_TIMEOUT_S = 60.0


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


def _create_subscriber(ctx, ebv2, bus_arn: str, invoke: dict, **kwargs) -> dict:
    """A subscriber on ``bus_arn``, deleted at cleanup."""
    sub = ebv2.create_subscriber(
        Name=kwargs.pop("Name", None) or ctx.unique_name("sim2real-behav-ebv2-sub-"),
        EventBusArn=bus_arn,
        ClientToken=ctx.unique_name("sim2real-behav-stok-"),
        InvokeConfiguration=invoke,
        **kwargs,
    )
    _track_subscriber(ctx, ebv2, sub)
    return sub


def _track_subscriber(ctx, ebv2, sub: dict) -> None:
    arn = sub["SubscriberArn"]
    ctx.on_cleanup(_teardown(lambda: ebv2.delete_subscriber(SubscriberArn=arn),
                             "ResourceNotFoundException"))


def _unused_target(ctx) -> tuple[str, str]:
    """(RoleArn, TargetArn) in the caller's account; the control-plane calls here invoke neither."""
    return (f"arn:aws:iam::{ctx.account}:role/sim2real-behav-ebv2-unused-role",
            f"arn:aws:sqs:{ctx.region}:{ctx.account}:sim2real-behav-ebv2-unused-q")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Each resource keeps its own tag set: tags on a bus, at creation or added later, never appear
    on its subscribers or event sources, and a subscriber's own tags never reach the bus.
    
    Reference: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-custom-bus-access-actions.html
    """
    ebv2 = ctx.client("eventbridgev2")
    bus_arn = _create_bus(ctx, ebv2, Tags={"sim2real-scope": "bus"})["EventBusArn"]
    role_arn, target_arn = _unused_target(ctx)
    sub = _create_subscriber(ctx, ebv2, bus_arn,
                             {"RoleArn": role_arn, "TargetArn": target_arn, "SqsParameters": {}},
                             Tags={"sim2real-scope": "subscriber"})
    source = ebv2.create_event_source(
        Name=ctx.unique_name("sim2real-behav-ebv2-src-"), EventBusArn=bus_arn,
        ClientToken=ctx.unique_name("sim2real-behav-stok-"),
        Configuration={"AwsServiceEventsConfiguration": {"AwsService": "aws.ec2"}})
    source_arn = source["EventSourceArn"]
    ctx.on_cleanup(_teardown(lambda: ebv2.delete_event_source(EventSourceArn=source_arn),
                             "ResourceNotFoundException"))

    ebv2.tag_resource(ResourceArn=bus_arn, Tags={"sim2real-added": "later"})

    def tags_of(arn):
        return ebv2.list_tags_for_resource(ResourceArn=arn).get("Tags", {})

    assert tags_of(bus_arn) == {"sim2real-scope": "bus", "sim2real-added": "later"}, (
        f"the bus carries {tags_of(bus_arn)!r}"
    )
    assert tags_of(sub["SubscriberArn"]) == {"sim2real-scope": "subscriber"}, (
        f"the subscriber carries {tags_of(sub['SubscriberArn'])!r}, expected only its own tag"
    )
    assert tags_of(source_arn) == {}, f"the event source carries {tags_of(source_arn)!r}, expected none"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
