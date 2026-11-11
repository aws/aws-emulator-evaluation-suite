"""alarm-unit-and-percentile-traps-statistic-set-percentile-is-empty-not-fabricated."""
from __future__ import annotations

# On real AWS, a series published only as StatisticValues
# {SampleCount 10, Sum 1000, Minimum 50, Maximum 200} returns GetMetricData Stat='p90' with
# StatusCode 'Complete' and Values [] (no error, no number), while Sum and Maximum return values.
# A p90 alarm (EvaluateLowSampleCountPercentile='evaluate') over it stayed INSUFFICIENT_DATA
# ('Unchecked: Initial alarm creation'); a Maximum alarm over the same series reached ALARM on 200.

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-unit-and-percentile-traps-statistic-set-percentile-is-empty-not-fabricated"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_THRESHOLD = 10.0
_SET = {"SampleCount": 10.0, "Sum": 1000.0, "Minimum": 50.0, "Maximum": 200.0}
_RAW_VALUE = 100.0
_HOLD_S = 120.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics",
      "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A percentile over a statistic-set-only series does not exist -- on the query path AND to
    the alarm evaluator -- while the same series' Sum/Maximum do."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealStatSetNs")

    def _publish() -> None:
        now = datetime.now(timezone.utc)
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {"MetricName": "SetOnly", "Timestamp": now, "StatisticValues": dict(_SET),
                 "Unit": "Milliseconds"},
                {"MetricName": "RawValues", "Timestamp": now, "Value": _RAW_VALUE,
                 "Unit": "Milliseconds"},
            ],
        )

    def _create(name, metric, **stat):
        cw.put_metric_alarm(
            AlarmName=name, Namespace=namespace, MetricName=metric, Period=60,
            EvaluationPeriods=1, DatapointsToAlarm=1, Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanThreshold", TreatMissingData="missing",
            ActionsEnabled=False, AlarmDescription=f"sim2real statset {metric}",
            Tags=[{"Key": "sim2real-check", "Value": CHECK}], **stat,
        )

    _publish()
    set_p90 = ctx.unique_name("sim2real-statset-p90-")
    _create(set_p90, "SetOnly", ExtendedStatistic="p90", EvaluateLowSampleCountPercentile="evaluate")
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[set_p90]))
    set_max = ctx.unique_name("sim2real-statset-max-")
    _create(set_max, "SetOnly", Statistic="Maximum")
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[set_max]))
    raw_p90 = ctx.unique_name("sim2real-statset-rawp90-")
    _create(raw_p90, "RawValues", ExtendedStatistic="p90", EvaluateLowSampleCountPercentile="evaluate")
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[raw_p90]))

    first = _describe(cw, set_p90)
    assert first.get("ExtendedStatistic") == "p90" and first["StateValue"] == "INSUFFICIENT_DATA", (
        f"the statistic-set p90 alarm read back ExtendedStatistic={first.get('ExtendedStatistic')!r} "
        f"state={first['StateValue']!r}; expected p90 / INSUFFICIENT_DATA"
    )
    baseline_reason = first.get("StateReason")

    # --- beat 1: both controls fire ------------------------------------------------------------ #
    fired = _poll_until(
        lambda: {"max": _describe(cw, set_max), "raw": _describe(cw, raw_p90)},
        lambda d: all(a["StateValue"] == "ALARM" for a in d.values()),
        timeout_s=420.0, interval_s=15.0, on_iteration=_publish,
        description="the statistic-set Maximum alarm and the raw-series p90 alarm reached ALARM",
    )
    max_window = json.loads(fired["max"]["StateReasonData"]).get("recentDatapoints")
    assert max_window == [_SET["Maximum"]], (
        f"the Maximum control fired over {max_window!r}, expected [{_SET['Maximum']!r}]"
    )
    raw_window = json.loads(fired["raw"]["StateReasonData"]).get("recentDatapoints")
    assert raw_window == [_RAW_VALUE], (
        f"the raw-series p90 control fired over {raw_window!r}, expected [{_RAW_VALUE!r}]"
    )

    # --- beat 2: the percentile alarm over the statistic set stays starved --------------------- #
    readings = []
    t_end = time.monotonic() + _HOLD_S
    while True:
        _publish()
        readings.append(_describe(cw, set_p90))
        if time.monotonic() >= t_end:
            break
        time.sleep(20.0)
    states = [r["StateValue"] for r in readings]
    assert set(states) == {"INSUFFICIENT_DATA"}, (
        f"the p90 alarm over a StatisticValues-only series moved during the hold: {states!r}. "
        f"A statistic set with Minimum != Maximum carries no distribution, so there is no p90 to "
        f"evaluate -- a transition means the target fabricated one"
    )
    reasons = {r.get("StateReason") for r in readings}
    assert reasons == {baseline_reason}, (
        f"the statistic-set p90 alarm's StateReason moved from {baseline_reason!r} to {sorted(reasons)!r}"
    )
    alarm_items = [i for i in _state_updates(cw, set_p90) if _new_state(i) == "ALARM"]
    assert alarm_items == [], f"the statistic-set p90 alarm's history records {alarm_items!r}"

    # --- beat 3: GetMetricData refuses to invent the number ------------------------------------ #
    end = datetime.now(timezone.utc) + timedelta(minutes=1)
    start = end - timedelta(minutes=20)

    def _q(qid, metric, stat):
        return {"Id": qid, "MetricStat": {
            "Metric": {"Namespace": namespace, "MetricName": metric}, "Period": 60, "Stat": stat}}

    res = cw.get_metric_data(
        MetricDataQueries=[
            _q("setp90", "SetOnly", "p90"), _q("setsum", "SetOnly", "Sum"),
            _q("setmax", "SetOnly", "Maximum"), _q("rawp90", "RawValues", "p90"),
        ],
        StartTime=start, EndTime=end,
    )["MetricDataResults"]
    by_id = {r["Id"]: r for r in res}
    assert by_id["setp90"]["StatusCode"] == "Complete" and by_id["setp90"]["Values"] == [], (
        f"GetMetricData p90 over the statistic-set series returned {by_id['setp90']!r}; expected "
        f"StatusCode Complete with NO values, never a fabricated percentile"
    )
    sums = by_id["setsum"]["Values"]
    assert sums and all(v > 0 and abs(v / _SET["Sum"] - round(v / _SET["Sum"])) < 1e-9 for v in sums), (
        f"GetMetricData Sum over the statistic-set series returned {sums!r}; expected positive "
        f"multiples of {_SET['Sum']} (one per statistic set aggregated into the period)"
    )
    assert by_id["setmax"]["Values"] and set(by_id["setmax"]["Values"]) == {_SET["Maximum"]}, (
        f"GetMetricData Maximum over the statistic-set series returned {by_id['setmax']['Values']!r}"
    )
    assert by_id["rawp90"]["Values"] and set(by_id["rawp90"]["Values"]) == {_RAW_VALUE}, (
        f"GetMetricData p90 over the raw series returned {by_id['rawp90']['Values']!r}; expected "
        f"{_RAW_VALUE} -- the percentile path works where raw values exist"
    )


# ===== helpers =====
def _describe(cw, alarm_name):
    for page in cw.get_paginator("describe_alarms").paginate(
        AlarmNames=[alarm_name], AlarmTypes=["MetricAlarm"]
    ):
        for alarm in page.get("MetricAlarms", []):
            if alarm["AlarmName"] == alarm_name:
                return alarm
    raise AssertionError(f"alarm {alarm_name!r} is not present in DescribeAlarms")


def _state_updates(cw, alarm_name):
    items = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=alarm_name, HistoryItemType="StateUpdate", ScanBy="TimestampAscending"
    ):
        items.extend(page.get("AlarmHistoryItems", []))
    return items


def _new_state(item) -> str:
    return json.loads(item["HistoryData"]).get("newState", {}).get("stateValue", "")


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
