"""alarm-m-of-n-holds-at-m-minus-one-and-fires-at-m."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-m-of-n-holds-at-m-minus-one-and-fires-at-m"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_THRESHOLD = 10.0
_BREACH = 99.0
_CLEAR = 1.0
_N = 5
_M = 3
#: Minutes after the seeded one that hold a clear value before the alarms exist.
_PREFILL_MINUTES = 10


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A 3-of-5 alarm stays OK with 2 breaching datapoints in its window and fires on the third, while
    a 5-of-5 control on the same metric stays OK; the state reasons report the datapoints counted.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealMofNNs")
    metric = "WindowMetric"
    alarm_name = ctx.unique_name("sim2real-mofn-")
    control_name = ctx.unique_name("sim2real-mofn-control-")

    def _publish_at(stamp: datetime, value: float) -> None:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {"MetricName": metric, "Timestamp": stamp, "Value": value, "Unit": "Count"}
            ],
        )

    def _publish(offset_minutes: int, value: float) -> None:
        _publish_at(_minute_floor() - timedelta(minutes=offset_minutes), value)

    def _create(name: str, datapoints_to_alarm: int) -> None:
        cw.put_metric_alarm(
            AlarmName=name,
            Namespace=namespace,
            MetricName=metric,
            Statistic="Maximum",
            Period=60,
            EvaluationPeriods=_N,
            DatapointsToAlarm=datapoints_to_alarm,
            Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanThreshold",
            # notBreaching + a hole-free series: a missing period is NOT neutral, because CloudWatch
            # carries the most recent valid datapoint forward, which would inflate the breach count.
            TreatMissingData="notBreaching",
            ActionsEnabled=False,
            AlarmDescription="sim2real depth: M-of-N is a count over a sliding window",
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )

    # Seed a hole-free 5-period window holding exactly 2 breaching datapoints, BEFORE the alarms
    # exist, so their first evaluation already has the M-1 window to read. The two breaches sit at
    # the NEWEST two periods deliberately, for two reasons: the window slides forward while this
    # check runs, and only the newest positions survive that slide long enough to be asserted; and
    # an emulator that compares the newest datapoint to the threshold sees a breach and fires,
    # which is exactly the shortcut leg A must catch. Every seed is stamped relative to ONE minute,
    # so the series cannot straddle a minute boundary while it is published. The minutes after the
    # seeded one are pre-filled with clear values (PutMetricData accepts timestamps up to two hours
    # ahead), so a window that slides onto a new minute never sees a hole before a poll fills it.
    base = _minute_floor()
    for offset, value in ((4, _CLEAR), (3, _CLEAR), (2, _CLEAR), (1, _BREACH), (0, _BREACH)):
        _publish_at(base - timedelta(minutes=offset), value)
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[
            {
                "MetricName": metric,
                "Timestamp": base + timedelta(minutes=ahead),
                "Value": _CLEAR,
                "Unit": "Count",
            }
            for ahead in range(1, _PREFILL_MINUTES + 1)
        ],
    )

    # The alarms' first evaluation reads the full seeded window only once ingestion shows all of it;
    # an evaluation over a partly ingested window cites fewer than N datapoints.
    _poll_until(
        lambda: cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric,
            StartTime=base - timedelta(minutes=_N - 1),
            EndTime=base + timedelta(minutes=1),
            Period=60,
            Statistics=["Maximum"],
        )["Datapoints"],
        lambda points: len(points) == _N,
        timeout_s=_budget(ctx, 90.0, 30.0),
        interval_s=2.0,
        description=f"the {_N} seeded datapoints visible to GetMetricStatistics",
    )
    # The alarms exist only once the seeded minute has ended. An evaluator that counts only ended
    # periods and one that also counts the current period then both see 5 values, 2 of them breaching.
    _sleep_until(ctx, base + timedelta(minutes=1, seconds=1))

    _create(alarm_name, _M)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    _create(control_name, _N)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[control_name]))

    # Every new alarm starts in INSUFFICIENT_DATA; the data already exists, so its first evaluation
    # may land before this read. The start state is proven by the oldest history item below.
    initial = _describe(cw, alarm_name)
    assert initial["StateValue"] in ("INSUFFICIENT_DATA", "OK"), (
        f"a freshly created alarm over a 2-of-5 breaching window reported "
        f"{initial['StateValue']!r}; it starts in INSUFFICIENT_DATA and may only evaluate to OK"
    )
    assert (initial["EvaluationPeriods"], initial["DatapointsToAlarm"]) == (_N, _M), (
        f"the configuration under test did not round-trip: EvaluationPeriods="
        f"{initial['EvaluationPeriods']!r}, DatapointsToAlarm={initial['DatapointsToAlarm']!r}, "
        f"expected {(_N, _M)!r}"
    )

    # --- leg A: 2 of 5 breaching, M=3 -> the engine evaluates and declines to fire ----------------
    # StateUpdatedTimestamp only moves on a transition, so the OK is proven by its own
    # recentDatapoints containing the two breaches it declined to fire on.
    # Leg B needs both seeded breaches still inside the window, so leg A settles within 3 minutes
    # of the seeded minute.
    horizon_s = (base + timedelta(minutes=3) - datetime.now(timezone.utc)).total_seconds()
    ok = _poll_until(
        lambda: _describe(cw, alarm_name),
        lambda a: a["StateValue"] == "OK",
        timeout_s=max(1.0, min(_budget(ctx, 300.0, 30.0), horizon_s)),
        interval_s=2.0,
        description=(
            f"alarm {alarm_name!r} produced an evaluated OK over a 5-period window holding 2 "
            f"breaching datapoints"
        ),
        on_iteration=lambda: _publish(0, _CLEAR),
    )
    srd_ok = json.loads(ok["StateReasonData"])
    window = srd_ok["recentDatapoints"]
    assert len(window) == _N, (
        f"the engine's recentDatapoints hold {len(window)} values {window!r}; a 5-period alarm "
        f"evaluates a 5-period window, so a shorter list means the window is not being tracked"
    )
    assert sorted(window) == sorted([_BREACH, _CLEAR, _BREACH, _CLEAR, _CLEAR]), (
        f"the values the engine compared are {window!r}; expected this check's published series "
        f"aggregated to a per-period Maximum, i.e. two {_BREACH!r} and three {_CLEAR!r}"
    )
    breaching_in_window = [v for v in window if v > _THRESHOLD]
    assert len(breaching_in_window) == _M - 1, (
        f"the window the engine evaluated holds {len(breaching_in_window)} values above the "
        f"threshold ({breaching_in_window!r}); leg A requires exactly {_M - 1} so that M is one "
        f"short"
    )
    assert ok["StateValue"] == "OK", f"{ok!r}"
    # Verbatim from real AWS: the OK direction's minimum is EvaluationPeriods - DatapointsToAlarm + 1
    # non-breaching datapoints, so this one string pins BOTH integers of the configuration.
    assert (
        f"minimum {_N - _M + 1} datapoints for ALARM -> OK transition" in ok["StateReason"]
    ), (
        f"the OK verdict's StateReason is {ok['StateReason']!r}; real CloudWatch names the "
        f"predicate it applied, and for DatapointsToAlarm={_M} of EvaluationPeriods={_N} the OK "
        f"direction needs a minimum of {_N - _M + 1} non-breaching datapoints"
    )
    assert f"out of the last {_N} datapoints" in ok["StateReason"], (
        f"the OK verdict's StateReason is {ok['StateReason']!r} and does not name the {_N}-period "
        f"window; an emulator that dropped EvaluationPeriods reports a different denominator"
    )
    evaluated_ok = srd_ok["evaluatedDatapoints"]
    assert len(evaluated_ok) == _N - _M + 1 and {d["value"] for d in evaluated_ok} == {_CLEAR}, (
        f"the engine's evaluatedDatapoints for the OK verdict are {evaluated_ok!r}; real CloudWatch "
        f"lists exactly the {_N - _M + 1} datapoints that satisfied the predicate, all of them the "
        f"non-breaching {_CLEAR!r} -- it is the justification, not the window"
    )

    # --- leg B: one further breaching datapoint puts M of N in the window -> ALARM -----------------
    # Pinned to the first pre-filled clear minute after the seeded ones: every window that ends from
    # that minute through base+3 holds it and both seeded breaches, whenever leg A settled.
    # Re-published unchanged on every poll pass: PutMetricData with a per-period Maximum statistic
    # is idempotent for a repeated value, so the breach count in the window stays exactly M.
    breach_stamp = base + timedelta(minutes=1)
    _publish_at(breach_stamp, _BREACH)
    fired = _poll_until(
        lambda: _describe(cw, alarm_name),
        lambda a: a["StateValue"] == "ALARM",
        timeout_s=_budget(ctx, 300.0, 15.0),
        interval_s=2.0,
        description=(
            f"alarm {alarm_name!r} fired once the {_M}th breaching datapoint entered the "
            f"{_N}-period window; no set_alarm_state call exists anywhere in this file"
        ),
        on_iteration=lambda: _publish_at(breach_stamp, _BREACH),
    )
    srd_alarm = json.loads(fired["StateReasonData"])
    fired_window = srd_alarm["recentDatapoints"]
    breaching_at_fire = [v for v in fired_window if v > _THRESHOLD]
    assert len(breaching_at_fire) == _M, (
        f"the alarm fired with {len(breaching_at_fire)} breaching values in its window "
        f"({fired_window!r}); it must fire on exactly the {_M}th, so a different count means the "
        f"predicate is not a count over the window"
    )
    assert f"{_M} out of the last {_N} datapoints" in fired["StateReason"], (
        f"the ALARM StateReason is {fired['StateReason']!r}; real CloudWatch names both integers "
        f"as '{_M} out of the last {_N} datapoints'. An emulator that dropped DatapointsToAlarm "
        f"says '{_N} out of the last {_N}' or omits the phrase"
    )
    assert f"minimum {_M} datapoints for OK -> ALARM transition" in fired["StateReason"], (
        f"the ALARM StateReason is {fired['StateReason']!r}; the OK->ALARM direction's minimum is "
        f"DatapointsToAlarm={_M}, and real CloudWatch states it verbatim"
    )
    assert srd_alarm["threshold"] == _THRESHOLD, (
        f"the ALARM decision recorded threshold {srd_alarm['threshold']!r}, expected "
        f"{_THRESHOLD!r} echoed from the alarm's configuration"
    )
    evaluated_alarm = srd_alarm["evaluatedDatapoints"]
    assert len(evaluated_alarm) == _M and {d["value"] for d in evaluated_alarm} == {_BREACH}, (
        f"the engine's evaluatedDatapoints for the ALARM verdict are {evaluated_alarm!r}; real "
        f"CloudWatch lists exactly the {_M} breaching datapoints it counted, all valued {_BREACH!r}"
    )
    stamps = sorted(d["timestamp"] for d in evaluated_alarm)
    assert len(set(stamps)) == _M, (
        f"the {_M} counted datapoints carry {len(set(stamps))} distinct timestamps ({stamps!r}); "
        f"they must be {_M} DIFFERENT periods, not one period counted repeatedly"
    )

    # --- the transition came from the asserted OK, so both legs are one alarm's history -----------
    updates = _poll_until(
        lambda: _state_updates(cw, alarm_name),
        lambda items: any(
            json.loads(i["HistoryData"]).get("newState", {}).get("stateValue") == "ALARM"
            for i in items
        ),
        timeout_s=_budget(ctx, 90.0),
        interval_s=2.0,
        description=f"a StateUpdate history item recording the ALARM transition on {alarm_name!r}",
    )
    hist = next(
        json.loads(i["HistoryData"])
        for i in updates
        if json.loads(i["HistoryData"]).get("newState", {}).get("stateValue") == "ALARM"
    )
    assert hist["oldState"]["stateValue"] == "OK", (
        f"the ALARM transition recorded in history came from "
        f"{hist['oldState']['stateValue']!r}; it must come from the OK asserted in leg A, which is "
        f"what makes leg A and leg B the same alarm's history rather than two observations"
    )
    first = json.loads(updates[-1]["HistoryData"])
    assert (first["oldState"]["stateValue"], first["newState"]["stateValue"]) == (
        "INSUFFICIENT_DATA",
        "OK",
    ), (
        f"the alarm's first StateUpdate went {first['oldState']['stateValue']!r} -> "
        f"{first['newState']['stateValue']!r}; every new CloudWatch alarm starts in "
        f"INSUFFICIENT_DATA regardless of the data already in the metric, and leg A's OK is its "
        f"first evaluation"
    )

    # --- negative space: the M=N control saw the same data and must NOT have fired -----------------
    control = _describe(cw, control_name)
    assert control["StateValue"] == "OK", (
        f"the control alarm (DatapointsToAlarm={_N}=EvaluationPeriods) reports "
        f"{control['StateValue']!r} with reason {control['StateReason']!r}; only "
        f"{len(breaching_at_fire)} of {_N} datapoints breached, so a {_N}-of-{_N} predicate cannot "
        f"be satisfied. Its firing would mean the ALARM above was caused by the data alone"
    )
    assert control["DatapointsToAlarm"] == _N, (
        f"the control's DatapointsToAlarm is {control['DatapointsToAlarm']!r}, expected {_N!r}"
    )

    # --- cleanup is verified, not assumed ---------------------------------------------------------
    cw.delete_alarms(AlarmNames=[alarm_name, control_name])
    assert _describe_all(cw, [alarm_name, control_name]) == [], (
        f"DeleteAlarms left {_describe_all(cw, [alarm_name, control_name])!r} behind"
    )


def _budget(ctx, cap_s, reserve_s=5.0):
    """A wait's cap, cut to the runner's remaining time so the check fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - reserve_s))


def _sleep_until(ctx, instant: datetime) -> None:
    """Sleep until the wall clock passes *instant*; raise not-graded when the run budget ends first."""
    wait_s = (instant - datetime.now(timezone.utc)).total_seconds()
    if wait_s <= 0:
        return
    left = ctx.time_left()
    if left is not None and wait_s > left - 30.0:
        raise TimeoutError(f"waiting {wait_s:.0f}s for the seeded minute to end; not graded")
    time.sleep(wait_s)


def _minute_floor() -> datetime:
    return datetime.now(timezone.utc).replace(second=0, microsecond=0)


def _describe_all(cw, names):
    """Every metric alarm in *names*, via a paginated DescribeAlarms.

    Paginated because other alarms in the account can push a result off page one.
    """
    out = []
    for page in cw.get_paginator("describe_alarms").paginate(
        AlarmNames=list(names), AlarmTypes=["MetricAlarm"]
    ):
        out.extend(page.get("MetricAlarms", []))
    return out


def _describe(cw, alarm_name):
    for alarm in _describe_all(cw, [alarm_name]):
        if alarm["AlarmName"] == alarm_name:
            return alarm
    raise AssertionError(f"alarm {alarm_name!r} is not present in DescribeAlarms")


def _state_updates(cw, alarm_name):
    items = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=alarm_name, HistoryItemType="StateUpdate", ScanBy="TimestampDescending"
    ):
        items.extend(page.get("AlarmHistoryItems", []))
    return items


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, on_iteration=None):
    """Poll probe() until predicate(result); FAIL on exhaustion, never skip."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not happen within {timeout_s}s; last observation {last!r}"
            )
        if on_iteration is not None:
            on_iteration()
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
