"""put-log-events-oversized-batch-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-log-events-oversized-batch-rejected"
GROUP = "representation"
SERVICES = ["logs"]

# The documented cap is on the whole batch: UTF-8 message bytes plus 26 bytes per event must not
# exceed 1,048,576. The overflow is spread across several individually small events.
_MAX_BATCH_BYTES = 1_048_576
_PER_EVENT_OVERHEAD_BYTES = 26
_BATCH_EVENT_COUNT = 4


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A batch of small events one byte over the 1,048,576-byte batch cap is rejected with
    InvalidParameterException and nothing is stored; the same shape at the cap is accepted.
    """
    logs = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-logs-")
    stream = "oversized-batch-stream"

    logs.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=group))
    logs.create_log_stream(logGroupName=group, logStreamName=stream)

    base_ms = int(time.time() * 1000)

    logs.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": base_ms, "message": "small-control-event"}],
    )
    events = _poll_for_events(ctx, group, stream, expected_count=1)
    assert len(events) == 1 and events[0]["message"] == "small-control-event"

    oversized_batch = _batch_of_total_bytes(
        _MAX_BATCH_BYTES + 1, _BATCH_EVENT_COUNT, base_ms + 1, filler="o"
    )
    for evt in oversized_batch:
        assert len(evt["message"].encode("utf-8")) < _MAX_BATCH_BYTES // 2, (
            "each event must be individually small so the failure isolates the "
            "batch-total rule, not a single-message-size rule"
        )
    code, message = _error(
        lambda: logs.put_log_events(
            logGroupName=group, logStreamName=stream, logEvents=oversized_batch
        )
    )
    assert code == "InvalidParameterException", f"unexpected error code: {code}"
    expected = f"Upload too large: {_MAX_BATCH_BYTES + 1} bytes exceeds limit of {_MAX_BATCH_BYTES}"
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # Polled because GetLogEvents is eventually consistent on the read side.
    events_after = _poll_for_events(ctx, group, stream, expected_count=1)
    assert len(events_after) == 1, (
        "oversized batch was partially or fully stored despite rejection: "
        f"messages={[e['message'][:20] for e in events_after]}"
    )
    assert events_after[0]["message"] == "small-control-event"
    assert not any(e["message"].startswith("o") for e in events_after), (
        f"a filler event from the rejected batch leaked in: {events_after!r}"
    )

    boundary_batch = _batch_of_total_bytes(
        _MAX_BATCH_BYTES, _BATCH_EVENT_COUNT, base_ms + 1000, filler="b"
    )
    accepted = logs.put_log_events(
        logGroupName=group, logStreamName=stream, logEvents=boundary_batch
    )
    assert "rejectedLogEventsInfo" not in accepted, (
        f"the at-cap batch must be accepted with no rejection report, got {accepted!r}"
    )
    events_final = _poll_for_events(ctx, group, stream, expected_count=1 + _BATCH_EVENT_COUNT)
    boundary_messages = [e["message"] for e in events_final if e["message"].startswith("b")]
    assert len(boundary_messages) == _BATCH_EVENT_COUNT, (
        f"expected all {_BATCH_EVENT_COUNT} at-cap events to be stored, got {events_final!r}"
    )


def _batch_of_total_bytes(total_bytes, count, base_ts, filler):
    overhead = _PER_EVENT_OVERHEAD_BYTES * count
    payload_bytes = total_bytes - overhead
    assert payload_bytes > count, f"cannot spread {total_bytes} bytes over {count} events"
    base_len, extra = divmod(payload_bytes, count)
    events = []
    for i in range(count):
        length = base_len + (1 if i < extra else 0)
        events.append({"timestamp": base_ts + i, "message": filler * length})
    return events


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _read_all_events(logs, group, stream):
    # GetLogEvents caps each response at ~1 MB; follow nextForwardToken until it stops advancing.
    events = []
    token = None
    while True:
        kwargs = {
            "logGroupName": group,
            "logStreamName": stream,
            "startFromHead": True,
            "limit": 10000,
        }
        if token is not None:
            kwargs["nextToken"] = token
        resp = logs.get_log_events(**kwargs)
        page = resp.get("events", [])
        events.extend(page)
        next_token = resp.get("nextForwardToken")
        if not page or next_token == token:
            return events
        token = next_token


def _poll_for_events(ctx, group, stream, expected_count, timeout_s=30.0, interval_s=1.0):
    logs = ctx.client("logs")
    deadline = time.monotonic() + timeout_s
    events = []
    while time.monotonic() < deadline:
        events = _read_all_events(logs, group, stream)
        if len(events) >= expected_count:
            return events
        time.sleep(interval_s)
    raise AssertionError(
        f"expected {expected_count} events on {group}/{stream}, got {len(events)} after {timeout_s}s"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
