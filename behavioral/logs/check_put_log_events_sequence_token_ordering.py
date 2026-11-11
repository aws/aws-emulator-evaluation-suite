"""put-log-events-sequence-token-ordering."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-log-events-sequence-token-ordering"
GROUP = 'log-events'
SERVICES = ['logs']


def _make_events(messages, start_ts_ms, step_ms=10):
    return [{"timestamp": start_ts_ms + i * step_ms, "message": m} for i, m in enumerate(messages)]


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A second PutLogEvents batch with a wrong sequenceToken and earlier timestamps is accepted with no
    rejected events, and GetLogEvents returns both batches merged in timestamp order, not arrival order.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-seqorder-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    base_ts = int(time.time() * 1000)
    batch_1 = _make_events(["seq-batch1-a", "seq-batch1-b"], start_ts_ms=base_ts)
    resp1 = svc.put_log_events(logGroupName=group, logStreamName=stream, logEvents=batch_1)
    assert resp1.get("nextSequenceToken"), f"expected a nextSequenceToken in the response: {resp1!r}"

    # Deliberately wrong: not the token this stream actually issued, but digits-only so it clears
    # botocore's local param validation and actually reaches the service instead of being rejected
    # client-side.
    bogus_token = "1" * 40

    # Earlier than batch 1, so arrival order and timestamp order disagree -- an implementation that
    # merely appends in arrival order cannot pass the ordering assertion below by accident.
    batch_2 = _make_events(["seq-batch2-a", "seq-batch2-b"], start_ts_ms=base_ts - 5000)
    resp2 = svc.put_log_events(
        logGroupName=group, logStreamName=stream, logEvents=batch_2, sequenceToken=bogus_token
    )
    assert resp2.get("rejectedLogEventsInfo") is None, (
        f"PutLogEvents with a deliberately wrong sequenceToken must not reject the batch "
        f"(AWS ignores the token entirely): {resp2!r}"
    )
    assert resp2.get("nextSequenceToken"), (
        f"expected a nextSequenceToken even though the submitted token was bogus: {resp2!r}"
    )

    submission_order = ["seq-batch1-a", "seq-batch1-b", "seq-batch2-a", "seq-batch2-b"]
    timestamp_order = ["seq-batch2-a", "seq-batch2-b", "seq-batch1-a", "seq-batch1-b"]
    assert submission_order != timestamp_order, (
        "fixture sanity: submission order must differ from timestamp order, otherwise this check "
        "cannot distinguish the two"
    )

    got = _poll_until(
        lambda: svc.get_log_events(logGroupName=group, logStreamName=stream, startFromHead=True),
        lambda r: len(r.get("events", [])) == 4,
        timeout_s=30,
        interval_s=2.0,
        description="all 4 events across both batches land",
    )
    messages = [e["message"] for e in got["events"]]
    assert messages == timestamp_order, (
        f"events must be ordered by TIMESTAMP regardless of arrival order or sequenceToken "
        f"validity: got {messages!r}, expected {timestamp_order!r} (submission order was "
        f"{submission_order!r})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
