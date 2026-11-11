"""put-log-events-duplicate-detection."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-log-events-duplicate-detection"
GROUP = 'log-events'
SERVICES = ['logs']


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
    """Sending an identical PutLogEvents batch twice succeeds both times with a nextSequenceToken, and
    GetLogEvents returns both copies: the service does not deduplicate a resubmitted batch.
    """
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-dupdetect-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    ts = int(time.time() * 1000)
    identical_batch = [{"timestamp": ts, "message": "duplicate-payload-event"}]

    resp1 = svc.put_log_events(logGroupName=group, logStreamName=stream, logEvents=identical_batch)
    assert resp1.get("nextSequenceToken"), f"expected first submission to succeed: {resp1!r}"

    resp2 = svc.put_log_events(logGroupName=group, logStreamName=stream, logEvents=identical_batch)
    assert resp2.get("nextSequenceToken"), (
        f"expected the IDENTICAL second submission to succeed too (no dedup), got {resp2!r}"
    )

    got = _poll_until(
        lambda: svc.get_log_events(logGroupName=group, logStreamName=stream, startFromHead=True),
        lambda r: len(r.get("events", [])) == 2,
        timeout_s=30,
        interval_s=2.0,
        description="both copies of the duplicate batch are independently ingested",
    )
    messages = [e["message"] for e in got["events"]]
    assert messages == ["duplicate-payload-event", "duplicate-payload-event"], (
        f"expected the duplicate batch to be ingested twice (no server-side dedup), got {messages!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
