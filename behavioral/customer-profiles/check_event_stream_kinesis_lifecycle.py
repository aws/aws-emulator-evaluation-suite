"""event-stream-kinesis-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "event-stream-kinesis-lifecycle"
GROUP = "state"
SERVICES = ["customer-profiles"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateEventStream against a real Kinesis stream reaches State RUNNING; DeleteEventStream removes it (GetEventStream 404s)."""
    cp = ctx.client("customer-profiles")
    kinesis = ctx.client("kinesis")
    domain = ctx.unique_name("sim2real-cp-dom-")
    stream_name = ctx.unique_name("sim2real-cp-stream-")
    event_stream_name = ctx.unique_name("sim2real-cp-es-")

    kinesis.create_stream(StreamName=stream_name, ShardCount=1, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: kinesis.delete_stream(StreamName=stream_name, EnforceConsumerDeletion=True)
        )
    )
    kinesis.get_waiter("stream_exists").wait(StreamName=stream_name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    stream_arn = kinesis.describe_stream(StreamName=stream_name)["StreamDescription"]["StreamARN"]

    cp.create_domain(DomainName=domain, DefaultExpirationDays=30, Tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: cp.delete_domain(DomainName=domain)))

    cp.create_event_stream(
        DomainName=domain, EventStreamName=event_stream_name, Uri=stream_arn, Tags={"sim2real-check": CHECK}
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: cp.delete_event_stream(DomainName=domain, EventStreamName=event_stream_name)
        )
    )

    got = _poll_until(
        lambda: cp.get_event_stream(DomainName=domain, EventStreamName=event_stream_name),
        lambda r: r["State"] == "RUNNING",
        timeout_s=60,
    )
    assert got["EventStreamArn"].endswith(event_stream_name), (
        f"expected EventStreamArn to end with {event_stream_name!r}, got {got['EventStreamArn']!r}"
    )

    listed = cp.list_event_streams(DomainName=domain)
    listed_names = {i["EventStreamName"] for i in listed.get("Items", [])}
    assert event_stream_name in listed_names, (
        f"expected {event_stream_name!r} in ListEventStreams while running, got {listed_names}"
    )

    cp.delete_event_stream(DomainName=domain, EventStreamName=event_stream_name)
    code, message = _error(
        lambda: cp.get_event_stream(DomainName=domain, EventStreamName=event_stream_name)
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetEventStream after delete, got {code!r}"
    )
    assert message == (
        f"The EventStream with name {event_stream_name} not found for domain {domain}"
    ), f"unexpected GetEventStream message after delete: {message!r}"

    listed_after = cp.list_event_streams(DomainName=domain)
    listed_after_names = {i["EventStreamName"] for i in listed_after.get("Items", [])}
    assert event_stream_name not in listed_after_names, (
        f"expected {event_stream_name!r} absent from ListEventStreams after delete, got {listed_after_names}"
    )


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] not in ("ResourceNotFoundException", "LimitExceededException"):
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
