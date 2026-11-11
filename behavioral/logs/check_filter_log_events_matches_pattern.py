"""filter-log-events-matches-pattern."""
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

CHECK = "filter-log-events-matches-pattern"
GROUP = 'log-events'
SERVICES = ['logs']
def _now_ms() -> int:
    return int(time.time() * 1000)

_ERROR_MSG = "ERROR something broke"
_INFO_MSG = "INFO all good"

@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """FilterLogEvents returns only events whose message matches the filter pattern."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-filter-")
    stream = ctx.unique_name("sim2real-behav-stream-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))
    svc.create_log_stream(logGroupName=group, logStreamName=stream)

    ts = _now_ms()
    svc.put_log_events(
        logGroupName=group,
        logStreamName=stream,
        logEvents=[
            {"timestamp": ts, "message": _ERROR_MSG},
            {"timestamp": ts + 1, "message": _INFO_MSG},
        ],
    )

    def probe():
        return svc.filter_log_events(logGroupName=group, filterPattern="ERROR")

    resp = _poll_until(
        probe,
        lambda r: len(r.get("events", [])) >= 1,
        timeout_s=30,
        interval_s=2,
        description="filterPattern=ERROR returns at least one event",
    )
    messages = {e["message"] for e in resp["events"]}
    assert messages == {_ERROR_MSG}, (
        f"filterPattern=ERROR must select exactly the ERROR event and exclude the unrelated "
        f"INFO event, got {sorted(messages)!r}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
