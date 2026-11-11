"""event-source-lifecycle-against-active-bus."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-source-lifecycle-against-active-bus"
GROUP = "event-source"
SERVICES = ["eventbridgev2"]

_ACTIVE_TIMEOUT_S = 60.0


def _error_code_and_message(fn):
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


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


def _wait_bus_active(ebv2, bus_arn: str) -> None:
    deadline = time.monotonic() + _ACTIVE_TIMEOUT_S
    while True:
        described = ebv2.describe_event_bus(EventBusArn=bus_arn)
        if described["State"] == "ACTIVE":
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"bus stayed {described['State']!r}, never reached ACTIVE")
        time.sleep(2)


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEventSource on an ACTIVE bus answers ACTIVE directly; DescribeEventSource and
    ListEventSources agree, and DeleteEventSource removes it for both reads.
    """
    ebv2 = ctx.client("eventbridgev2")
    bus_name = ctx.unique_name("sim2real-behav-ebv2-bus-")
    source_name = ctx.unique_name("sim2real-behav-ebv2-src-")

    bus = ebv2.create_event_bus(Name=bus_name, ClientToken=ctx.unique_name("sim2real-behav-tok-"))
    bus_arn = bus["EventBusArn"]
    ctx.on_cleanup(_teardown_bus(ebv2, bus_arn))
    _wait_bus_active(ebv2, bus_arn)

    created = ebv2.create_event_source(
        Name=source_name,
        EventBusArn=bus_arn,
        ClientToken=ctx.unique_name("sim2real-behav-stok-"),
        Configuration={"AwsServiceEventsConfiguration": {"AwsService": "aws.ec2"}},
    )
    source_arn = created["EventSourceArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(
        lambda: ebv2.delete_event_source(EventSourceArn=source_arn)
    ))
    assert created["State"] == "ACTIVE", (
        f"CreateEventSource against an ACTIVE bus answered state {created['State']!r}, expected ACTIVE"
    )
    assert created["EventBusArn"] == bus_arn, (
        f"created source's EventBusArn {created['EventBusArn']!r} != {bus_arn!r}"
    )

    described = ebv2.describe_event_source(EventSourceArn=source_arn)
    assert described["Name"] == source_name, f"expected Name {source_name!r}, got {described['Name']!r}"
    assert described["State"] == "ACTIVE", f"expected ACTIVE, got {described['State']!r}"
    assert "Revoked" not in described, f"a fresh source must not report Revoked, got {described!r}"

    pages = ebv2.get_paginator("list_event_sources").paginate(EventBusArn=bus_arn)
    matches = [s for page in pages for s in page["EventSources"] if s["Name"] == source_name]
    assert len(matches) == 1, f"expected exactly one source named {source_name!r}, got {matches!r}"
    assert matches[0]["EventSourceArn"] == source_arn, (
        f"listed ARN {matches[0]['EventSourceArn']!r} != created ARN {source_arn!r}"
    )

    ebv2.delete_event_source(EventSourceArn=source_arn)
    code, message = _error_code_and_message(
        lambda: ebv2.describe_event_source(EventSourceArn=source_arn)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == f"EventSource not found: {source_arn}", f"unexpected message {message!r}"

    pages = ebv2.get_paginator("list_event_sources").paginate(EventBusArn=bus_arn)
    remaining = [s for page in pages for s in page["EventSources"] if s["Name"] == source_name]
    assert remaining == [], f"deleted source {source_name!r} still listed: {remaining!r}"


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
