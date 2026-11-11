"""put-log-events-batch-contract-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-log-events-batch-contract-rejected"
GROUP = 'log-events'
SERVICES = ['logs']

_HOUR_MS = 60 * 60 * 1000
_MAX_EVENTS_PER_BATCH = 10000


def _now_ms() -> int:
    return int(time.time() * 1000)


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutLogEvents rejects an unsorted batch, a batch spanning over 24 hours and one over 10,000
    events with InvalidParameterException, ingesting none of them; the control batch (the unsorted
    events, sorted) is accepted and becomes readable."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-batchcontract-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"sim2real-check": CHECK})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    now = _now_ms()

    def _messages():
        resp = svc.get_log_events(
            logGroupName=group,
            logStreamName=stream,
            startFromHead=True,
            startTime=now - 48 * _HOUR_MS,
            endTime=now + _HOUR_MS,
        )
        return [e["message"] for e in resp.get("events", [])]

    # --- 1. Events not in ascending timestamp order.
    unsorted_batch = [
        {"timestamp": now + 2000, "message": "unsorted-later"},
        {"timestamp": now, "message": "unsorted-earlier"},
    ]
    code_unsorted, msg_unsorted = _client_error(
        lambda: svc.put_log_events(
            logGroupName=group, logStreamName=stream, logEvents=unsorted_batch
        )
    )
    assert code_unsorted == "InvalidParameterException", (
        "a batch whose events are not in chronological order must be rejected with "
        f"InvalidParameterException, got {code_unsorted!r}"
    )
    assert msg_unsorted == (
        "Log events in a single PutLogEvents request must be in chronological order."
    ), f"unexpected message: {msg_unsorted!r}"

    # --- 2. Batch spanning more than 24 hours (both timestamps well inside the
    # 14-day retention window, so this isolates the SPAN rule).
    wide_span_batch = [
        {"timestamp": now - 25 * _HOUR_MS, "message": "span-first"},
        {"timestamp": now, "message": "span-last"},
    ]
    code_span, msg_span = _client_error(
        lambda: svc.put_log_events(
            logGroupName=group, logStreamName=stream, logEvents=wide_span_batch
        )
    )
    assert code_span == "InvalidParameterException", (
        "a batch spanning more than 24 hours must be rejected with "
        f"InvalidParameterException, got {code_span!r}"
    )
    assert msg_span == (
        "The batch of log events in a single PutLogEvents request cannot span more than 24 hours."
    ), f"unexpected message: {msg_span!r}"

    # --- 3. Batch exceeding the 10,000-events-per-request contract limit.
    oversized_batch = [
        {"timestamp": now + i, "message": f"oversized-{i}"}
        for i in range(_MAX_EVENTS_PER_BATCH + 1)
    ]
    code_size, msg_size = _client_error(
        lambda: svc.put_log_events(
            logGroupName=group, logStreamName=stream, logEvents=oversized_batch
        )
    )
    assert code_size == "InvalidParameterException", (
        f"a batch of {_MAX_EVENTS_PER_BATCH + 1} events must be rejected with "
        f"InvalidParameterException, got {code_size!r}"
    )
    assert msg_size == (
        "1 validation error detected: Value at 'logEvents' failed to satisfy constraint: "
        f"Member must have length less than or equal to {_MAX_EVENTS_PER_BATCH}"
    ), f"unexpected message: {msg_size!r}"

    # --- 4. Effect absent: no event from any rejected batch was ingested.
    leaked = [
        m
        for m in _messages()
        if m.startswith(("unsorted-", "span-", "oversized-"))
    ]
    assert leaked == [], (
        f"batch rejection must be all-or-nothing; these events leaked in: {leaked[:10]!r} "
        f"({len(leaked)} total)"
    )

    # --- 5. Control: the same events, sorted / in-span / under the cap, are
    # accepted and all become readable.
    control_batch = [
        {"timestamp": now, "message": "control-earlier"},
        {"timestamp": now + 2000, "message": "control-later"},
    ]
    accepted = svc.put_log_events(
        logGroupName=group, logStreamName=stream, logEvents=control_batch
    )
    assert "rejectedLogEventsInfo" not in accepted, (
        f"the control batch must be accepted with no rejection report, got {accepted!r}"
    )
    final = _poll_until(
        _messages,
        lambda msgs: msgs == ["control-earlier", "control-later"],
        timeout_s=60,
        interval_s=2.0,
        description="exactly the control batch is readable",
    )
    assert final == ["control-earlier", "control-later"], (
        f"expected only the control batch in the stream, got {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
