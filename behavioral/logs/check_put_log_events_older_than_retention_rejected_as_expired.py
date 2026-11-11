"""put-log-events-older-than-retention-rejected-as-expired."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "put-log-events-older-than-retention-rejected-as-expired"
GROUP = 'log-events'
SERVICES = ['logs']

_DAY_MS = 24 * 60 * 60 * 1000


# ===== helpers =====
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


# ===== end helpers =====


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """An event older than the log group's retention window but inside the 14-day floor is refused at
    ingest as ``expiredLogEventEndIndex`` and never stored, while the byte-identical batch is
    accepted by a control group that differs only in having no retention policy.
    """
    svc = ctx.client("logs")

    governed = ctx.unique_name("sim2real-behav-lg-expired-")
    control = ctx.unique_name("sim2real-behav-lg-expiredctl-")
    stream = ctx.unique_name("sim2real-behav-stream-")

    svc.create_log_group(logGroupName=governed, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=governed: svc.delete_log_group(logGroupName=_n))
    svc.create_log_group(logGroupName=control, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=control: svc.delete_log_group(logGroupName=_n))
    svc.create_log_stream(logGroupName=governed, logStreamName=stream)
    svc.create_log_stream(logGroupName=control, logStreamName=stream)

    # The single broken thing. The control group deliberately gets no retention
    # policy, so "never expire" is its window.
    svc.put_retention_policy(logGroupName=governed, retentionInDays=1)

    now = _now_ms()
    stale_ts = now - 3 * _DAY_MS
    stale = "sim2real-stale-event-3d-old"
    fresh = "sim2real-fresh-event"

    # Positive control, ACCEPTANCE half, submitted first: the byte-identical stale
    # batch into a group whose only difference is the absent retention policy.
    # Measured on real AWS: a backdated event takes appreciably longer to become
    # queryable than a current one, so this write goes in before the rejection legs
    # rather than after them -- the control's ingestion then overlaps the retention
    # poll and the settle window instead of serialising behind them.
    control_resp = svc.put_log_events(
        logGroupName=control,
        logStreamName=stream,
        logEvents=[{"timestamp": stale_ts, "message": stale}],
    )
    assert "rejectedLogEventsInfo" not in control_resp, (
        "positive control: with no retention policy the group's window is 'never expire', so the "
        f"identical 3-day-old event must be accepted outright, got {control_resp!r}"
    )

    def _retention():
        paginator = svc.get_paginator("describe_log_groups")
        for page in paginator.paginate(logGroupNamePrefix=governed):
            for grp in page.get("logGroups", []):
                if grp["logGroupName"] == governed:
                    return grp.get("retentionInDays")
        return None

    _poll_until(
        _retention,
        lambda days: days == 1,
        timeout_s=60,
        interval_s=2.0,
        description="DescribeLogGroups reports retentionInDays=1 on the governed group",
    )

    # A batch may not span more than 24 hours, so the stale event goes on its own.
    rejected_resp = svc.put_log_events(
        logGroupName=governed,
        logStreamName=stream,
        logEvents=[{"timestamp": stale_ts, "message": stale}],
    )
    info = rejected_resp.get("rejectedLogEventsInfo")
    assert info is not None, (
        "an event 3 days older than the group's 1-day retention window must be reported in "
        f"rejectedLogEventsInfo, got {rejected_resp!r} -- a 200 with no rejection report is the "
        "over-permissive outcome: the caller believes the write landed"
    )
    assert info.get("expiredLogEventEndIndex") == 1, (
        "expiredLogEventEndIndex is EXCLUSIVE, so a single retention-expired event at index 0 "
        f"must report 1, got {info!r}"
    )
    assert "tooOldLogEventEndIndex" not in info, (
        "a 3-day-old event is INSIDE the fixed 14-day floor, so it must be reported as expired "
        f"by retention and not as too old; got {info!r} -- an emulator reporting tooOld here is "
        "hardcoding 14 days and ignoring retentionInDays"
    )

    # An in-window event into the same stream, so the effect-absent read below is
    # over a stream that is provably being written to.
    accepted = svc.put_log_events(
        logGroupName=governed,
        logStreamName=stream,
        logEvents=[{"timestamp": now, "message": fresh}],
    )
    assert "rejectedLogEventsInfo" not in accepted, (
        f"an in-window event must be accepted with no rejection report, got {accepted!r}"
    )

    # No startTime/endTime on either read: startFromHead begins at the stream's
    # earliest event, so an unbounded read is strictly stronger for the
    # effect-absent leg -- nothing can hide outside a window that does not exist.
    def _messages(group):
        resp = svc.get_log_events(
            logGroupName=group, logStreamName=stream, startFromHead=True
        )
        return [e["message"] for e in resp.get("events", [])]

    _poll_until(
        lambda: _messages(governed),
        lambda msgs: fresh in msgs,
        timeout_s=90,
        interval_s=2.0,
        description="the in-window event becomes readable in the governed group",
    )

    # Effect absent, held across a bounded settle window so a late-arriving
    # ingestion cannot slip past a single-shot read.
    for _ in range(4):
        msgs = _messages(governed)
        assert msgs == [fresh], (
            "a retention-expired event must never be ingested; an unbounded GetLogEvents on the "
            f"governed stream returned {msgs!r}"
        )
        time.sleep(2.0)

    # Positive control, EFFECT half: the identical stale event IS readable from the
    # group that has no retention policy.
    control_msgs = _poll_until(
        lambda: _messages(control),
        lambda msgs: msgs == [stale],
        timeout_s=180,
        interval_s=3.0,
        description="the control group stores the identical stale event",
    )
    assert control_msgs == [stale], (
        "positive control: the retention policy must be the only reason the event was refused, so "
        f"the unpoliced group must hold exactly it; got {control_msgs!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
