"""op-contract-get-log-events."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-get-log-events"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetLogEvents with startFromHead=True returns events in insertion order with both pagination
    tokens, and a missing stream in an existing group gets ResourceNotFoundException and its message.
    """
    logs = ctx.client("logs")
    group_name = ctx.unique_name("sim2real-behav-lg-")
    stream_name = ctx.unique_name("sim2real-behav-ls-")

    logs.create_log_group(logGroupName=group_name, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group_name))
    logs.create_log_stream(logGroupName=group_name, logStreamName=stream_name)

    now_ms = int(time.time() * 1000)
    ordered_messages = [f"sim2real-behav-order-{i}" for i in range(3)]
    logs.put_log_events(
        logGroupName=group_name,
        logStreamName=stream_name,
        logEvents=[
            {"timestamp": now_ms + i * 10, "message": m} for i, m in enumerate(ordered_messages)
        ],
    )

    def _probe():
        return logs.get_log_events(
            logGroupName=group_name, logStreamName=stream_name, startFromHead=True
        )

    resp = _poll_until(
        _probe,
        lambda r: len(r.get("events", [])) >= 3,
        timeout_s=60,
        interval_s=3.0,
        description="all 3 ingested events visible via get_log_events",
    )
    got_messages = [e["message"] for e in resp["events"] if e["message"] in ordered_messages]
    assert got_messages == ordered_messages, f"events out of order: {got_messages}"
    assert "nextForwardToken" in resp, f"response missing nextForwardToken: {resp!r}"
    assert "nextBackwardToken" in resp, f"response missing nextBackwardToken: {resp!r}"

    # error boundary: log stream does not exist in an existing group
    code, message = _error(
        lambda: logs.get_log_events(
            logGroupName=group_name,
            logStreamName=ctx.unique_name("sim2real-behav-missing-ls-"),
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == "The specified log stream does not exist.", f"unexpected not-found message {message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
