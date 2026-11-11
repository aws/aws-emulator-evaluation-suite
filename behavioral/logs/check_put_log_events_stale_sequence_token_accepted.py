"""put-log-events-stale-sequence-token-accepted."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-log-events-stale-sequence-token-accepted"
GROUP = "concurrency"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutLogEvents batch with a stale sequenceToken is accepted with no rejected events and lands in
    the stream, while PutLogEvents to a nonexistent stream gets ResourceNotFoundException and its message.
    """
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-")
    stream = ctx.unique_name("sim2real-behav-ls-")
    logs.create_log_group(logGroupName=group, tags={"sim2real-check": "put-log-events-stale-sequence-token-accepted"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    now_ms = int(time.time() * 1000)
    first = logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": now_ms, "message": "sim2real-first-event"}],
    )
    assert first.get("rejectedLogEventsInfo") is None, (
        f"positive control: a batch with no sequenceToken at all was rejected: {first!r}"
    )

    # A sequenceToken that was never issued for this stream (wildly stale/bogus).
    bogus_token = "4" + "9" * 55
    second = logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        sequenceToken=bogus_token,
        logEvents=[{"timestamp": now_ms + 1, "message": "sim2real-second-event-stale-token"}],
    )
    assert second.get("rejectedLogEventsInfo") is None, (
        "batch sent with a stale sequenceToken was rejected; PutLogEvents should ignore "
        "sequenceToken entirely"
    )

    events = _wait_for_events(ctx, group, stream, expected_count=2, timeout_s=30)
    messages = {e["message"] for e in events}
    assert messages == {"sim2real-first-event", "sim2real-second-event-stale-token"}, (
        f"expected both events to land, got {messages!r}"
    )

    # The token is ignored, but the stream still has to exist: dropping sequence-token
    # enforcement is not license for an emulator to accept a write to a stream that was
    # never created.
    missing_stream = ctx.unique_name("sim2real-behav-ls-absent-")
    code, message = _error(
        lambda: logs.put_log_events(
            logGroupName=group,
            logStreamName=missing_stream,
            sequenceToken=bogus_token,
            logEvents=[{"timestamp": now_ms + 2, "message": "should-not-land"}],
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent stream regardless of the "
        f"(bogus) sequenceToken, got {code!r}"
    )
    assert message == "The specified log stream does not exist.", f"unexpected not-found message {message!r}"


def _error(fn):
    """The (code, message) of fn()'s ClientError; a success raises because AWS refuses the call."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _wait_for_events(ctx, group, stream, expected_count, timeout_s=30.0):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    events: list[dict] = []
    while time.monotonic() < deadline:
        events = []
        token = None
        while True:
            kwargs = {
                "logGroupName": group,
                "logStreamName": stream,
                "startFromHead": True,
            }
            if token is not None:
                kwargs["nextToken"] = token
            resp = logs.get_log_events(**kwargs)
            events.extend(resp["events"])
            new_token = resp.get("nextForwardToken")
            if new_token == token or not resp["events"]:
                break
            token = new_token
        if len(events) >= expected_count:
            return events
        time.sleep(1.0)
    raise AssertionError(f"expected {expected_count} events, saw {len(events)} within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
