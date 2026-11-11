"""alarm-evaluation-period-window."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-evaluation-period-window"
GROUP = 'alarms'
SERVICES = ['cloudwatch']


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """GetMetricStatistics over Period x EvaluationPeriods returns exactly EvaluationPeriods datapoints
    (fewer for a narrower window), and the alarm's own ALARM history record shows it evaluated that
    identical window: the evaluator must use the lookback its configuration defines."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-behav-cwprobe-ns-")
    metric_name = "LatencyMs"
    period = 60
    eval_periods = 3
    now = datetime.now(timezone.utc).replace(microsecond=0, second=0)
    name = ctx.unique_name("sim2real-behav-cwprobe-alarm-window-")

    values = {}
    for i in range(eval_periods):
        ts = now - timedelta(seconds=period * i)
        value = 10.0 + i
        values[i] = value
        cw.put_metric_data(
            Namespace=namespace, MetricData=[{"MetricName": metric_name, "Timestamp": ts, "Value": value}]
        )

    ctx.on_cleanup(lambda _n=name: cw.delete_alarms(AlarmNames=[_n]))
    cw.put_metric_alarm(
        AlarmName=name,
        Namespace=namespace,
        MetricName=metric_name,
        Statistic="Average",
        Period=period,
        EvaluationPeriods=eval_periods,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )

    def probe_full():
        resp = cw.get_metric_statistics(
            Namespace=namespace,
            MetricName=metric_name,
            StartTime=now - timedelta(seconds=period * eval_periods),
            EndTime=now + timedelta(seconds=period),
            Period=period,
            Statistics=["Average"],
        )
        return resp.get("Datapoints", [])

    full = _poll_until(
        probe_full,
        lambda dps: len(dps) >= eval_periods,
        timeout_s=60,
        interval_s=3,
        description=f"{eval_periods} periods visible within the alarm's lookback window",
    )
    assert len(full) == eval_periods, (
        f"expected exactly {eval_periods} periods within the alarm's Period*EvaluationPeriods "
        f"lookback window, got {len(full)}"
    )

    # Narrow the window to exactly the single most-recent period bucket
    # [now, now+period) -- GetMetricStatistics period buckets are aligned to
    # absolute clock boundaries, so a query starting exactly ON a bucket edge
    # (rather than mid-bucket) is the only way to exclude the adjacent
    # (now-period, now) bucket entirely.
    narrow_resp = cw.get_metric_statistics(
        Namespace=namespace,
        MetricName=metric_name,
        StartTime=now,
        EndTime=now + timedelta(seconds=period),
        Period=period,
        Statistics=["Average"],
    )
    narrow = narrow_resp.get("Datapoints", [])
    assert len(narrow) == 1, f"expected exactly 1 period in the narrowed (1-period-wide) window, got {narrow}"
    assert narrow[0]["Average"] == values[0], (
        f"expected the narrowed window's single period to be the i=0 datapoint, got {narrow}"
    )

    # The two GetMetricStatistics assertions above only infer what the alarm
    # evaluator itself uses as its lookback window. Confirm it at the alarm, not just at an
    # independently-constructed query: the evaluator must report evaluating exactly
    # `eval_periods` datapoints, at `period`-second spacing, over the SAME published values.
    # The window slides with the clock while the alarm waits for its evaluation, so every new
    # minute receives a datapoint too and the evaluated window always holds published values only.
    published = {now - timedelta(seconds=period * i): v for i, v in values.items()}

    def _state():
        minute = datetime.now(timezone.utc).replace(microsecond=0, second=0)
        if minute not in published:
            published[minute] = 10.0 + len(published)
            cw.put_metric_data(Namespace=namespace, MetricData=[
                {"MetricName": metric_name, "Timestamp": minute, "Value": published[minute]}])
        return cw.describe_alarms(AlarmNames=[name])["MetricAlarms"][0]["StateValue"]

    state = _poll_until(
        _state,
        lambda s: s == "ALARM",
        timeout_s=300,
        interval_s=10,
        description=f"alarm {name!r} transitioning to ALARM over its Period*EvaluationPeriods window",
    )
    assert state == "ALARM", f"alarm did not reach ALARM within its evaluation window: {state!r}"

    decision = _alarm_decision(cw, name)
    assert decision["period"] == period, (
        f"the alarm's own decision record reports period {decision['period']!r}, expected {period}"
    )
    assert len(decision["evaluatedDatapoints"]) == eval_periods, (
        f"the alarm evaluated {decision['evaluatedDatapoints']!r}; expected exactly {eval_periods} "
        f"datapoints, matching EvaluationPeriods and this check's own GetMetricStatistics window"
    )
    recent = decision["recentDatapoints"]
    assert len(recent) == eval_periods and set(recent) <= set(published.values()), (
        f"the alarm's recentDatapoints are {recent!r}, expected {eval_periods} of the published "
        f"values {sorted(published.values())!r} -- the evaluator's real window and this "
        f"check's independently-measured GetMetricStatistics window must agree"
    )
    stamps = sorted(datetime.strptime(d["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z")
                    for d in decision["evaluatedDatapoints"])
    assert all(t in published for t in stamps) and all(
        (b - a) == timedelta(seconds=period) for a, b in zip(stamps, stamps[1:])
    ), (
        f"the alarm evaluated datapoints at {[t.isoformat() for t in stamps]!r}; expected "
        f"{eval_periods} consecutive {period}-second periods this check published"
    )


# ===== helpers =====
def _alarm_decision(cw, alarm_name):
    """The `stateReasonData` of the ALARM transition recorded in the alarm's own history."""

    def _items():
        items = []
        for page in cw.get_paginator("describe_alarm_history").paginate(
            AlarmName=alarm_name, HistoryItemType="StateUpdate", ScanBy="TimestampDescending"
        ):
            items.extend(page.get("AlarmHistoryItems", []))
        return [json.loads(i["HistoryData"]) for i in items]

    deadline = time.monotonic() + 90.0
    while True:
        alarms = [h for h in _items() if h.get("newState", {}).get("stateValue") == "ALARM"]
        if alarms:
            return alarms[0]["newState"]["stateReasonData"]
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"no StateUpdate history item recording an ALARM transition for {alarm_name!r} "
                f"appeared within 90s; the alarm read ALARM but wrote no decision record"
            )
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
