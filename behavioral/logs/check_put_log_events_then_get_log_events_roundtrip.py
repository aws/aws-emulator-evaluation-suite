"""put-log-events-then-get-log-events-roundtrip."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-log-events-then-get-log-events-roundtrip"
GROUP = 'log-events'
SERVICES = ['logs']

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutLogEvents followed by GetLogEvents returns the same message content."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-events-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    ts = _now_ms()
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[{"timestamp": ts, "message": "hello-world-1"}],
    )

    def probe():
        return svc.get_log_events(
            logGroupName=group, logStreamName=stream, startFromHead=True
        )

    resp = _poll_until(
        probe,
        lambda r: len(r.get("events", [])) >= 1,
        timeout_s=30,
        interval_s=2,
    )
    messages = [e["message"] for e in resp["events"]]
    assert messages == ["hello-world-1"], (
        f"expected exactly the one written event back, got {messages!r}"
    )


def _now_ms() -> int:
    return int(time.time() * 1000)


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
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
