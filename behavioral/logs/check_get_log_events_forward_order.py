"""get-log-events-forward-order."""
from __future__ import annotations

import time

from behavioral_harness import tags

def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")

CHECK = "get-log-events-forward-order"
GROUP = 'log-events'
SERVICES = ['logs']
def _now_ms() -> int:
    return int(time.time() * 1000)

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetLogEvents with startFromHead=True returns events in ascending timestamp order."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-order-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    base = _now_ms()
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[
            {"timestamp": base, "message": "first"},
            {"timestamp": base + 10, "message": "second"},
            {"timestamp": base + 20, "message": "third"},
        ],
    )

    def probe():
        return svc.get_log_events(
            logGroupName=group, logStreamName=stream, startFromHead=True
        )

    resp = _poll_until(
        probe,
        lambda r: len(r.get("events", [])) >= 3,
        timeout_s=30,
        interval_s=2,
    )
    messages = [e["message"] for e in resp["events"]]
    assert messages == ["first", "second", "third"], messages

    timestamps = [e["timestamp"] for e in resp["events"]]
    assert timestamps == sorted(timestamps), (
        f"GetLogEvents(startFromHead=True) returned message order matching insertion order "
        f"but non-monotonic timestamps: {timestamps!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
