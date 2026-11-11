"""put-log-events-invalid-sequence-token-accepted."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-log-events-invalid-sequence-token-accepted"
GROUP = 'log-events'
SERVICES = ['logs']


def _make_events(messages, start_ts_ms=None, step_ms=1000):
    base = start_ts_ms if start_ts_ms is not None else int(time.time() * 1000)
    return [{"timestamp": base + i * step_ms, "message": m} for i, m in enumerate(messages)]


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded with {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutLogEvents with a wrong sequenceToken is accepted and its event lands in the stream, as AWS
    documents the token is not validated; PutLogEvents to a nonexistent stream still gets
    ResourceNotFoundException and its exact message.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-badtoken-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    bogus_token = "49999999999999999999999999999999999999999999999999999999"
    resp = svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=_make_events(["accepted-despite-bad-token"]),
        sequenceToken=bogus_token,
    )
    assert resp.get("nextSequenceToken"), (
        f"expected PutLogEvents to succeed despite a bogus sequenceToken, got {resp!r}"
    )
    got = _poll_until(
        lambda: svc.get_log_events(logGroupName=group, logStreamName=stream, startFromHead=True),
        lambda r: len(r.get("events", [])) == 1,
        timeout_s=30,
        interval_s=2.0,
        description="event ingested despite the invalid sequence token",
    )
    got_messages = [e["message"] for e in got["events"]]
    assert got_messages == ["accepted-despite-bad-token"], (
        f"expected exactly one ingested event with the accepted message, got {got_messages!r}"
    )

    missing_stream = ctx.unique_name("sim2real-behav-stream-absent-")
    code, message = _error(
        lambda: svc.put_log_events(
            logGroupName=group,
            logStreamName=missing_stream,
            logEvents=_make_events(["should-not-land"]),
            sequenceToken=bogus_token,
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a nonexistent stream regardless of token, got {code!r}"
    )
    assert message == "The specified log stream does not exist.", f"unexpected not-found message {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
