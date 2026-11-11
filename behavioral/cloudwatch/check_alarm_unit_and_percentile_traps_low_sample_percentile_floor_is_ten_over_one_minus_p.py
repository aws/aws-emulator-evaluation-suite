"""alarm-unit-and-percentile-traps-low-sample-percentile-floor-is-ten-over-one-minus-p."""
from __future__ import annotations

# For 0.5 <= p < 1, EvaluateLowSampleCountPercentile applies below 10/(1-p) data points per
# evaluation period (100 for p90, 1000 for p99), not a flat 10 samples.

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-unit-and-percentile-traps-low-sample-percentile-floor-is-ten-over-one-minus-p"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_THRESHOLD = 10.0
_VALUE = 100.0
#: metric -> samples per 60 s period. p90's floor is 10/(1-0.9) = 100; p99's is 1000.
_SAMPLES = {"P90Below": 99.0, "P90AtFloor": 100.0, "P99Below": 200.0}
_HOLD_S = 120.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics",
      "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """'ignore' withholds a percentile alarm below 10/(1-p) samples and evaluates at the floor:
    p90 at 99 is withheld, at 100 fires; p99 at 200 is withheld yet computable via GetMetricData.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html#percentiles-with-low-samples
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealPctFloorNs")
    last_minute = [None]

    def _minute() -> datetime:
        return datetime.now(timezone.utc).replace(second=0, microsecond=0)

    def _tick() -> None:
        """Publish each metric's sample count once per minute; the count per period is under test."""
        now = _minute()
        if now == last_minute[0]:
            return
        last_minute[0] = now
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {"MetricName": m, "Timestamp": now, "Values": [_VALUE], "Counts": [n],
                 "Unit": "Milliseconds"}
                for m, n in _SAMPLES.items()
            ],
        )

    specs = {
        "p90-99-ignore": ("P90Below", "p90", "ignore"),
        "p90-99-evaluate": ("P90Below", "p90", "evaluate"),
        "p90-100-ignore": ("P90AtFloor", "p90", "ignore"),
        "p99-200-ignore": ("P99Below", "p99", "ignore"),
        "p99-200-evaluate": ("P99Below", "p99", "evaluate"),
    }
    _tick()
    names = {}
    for key, (metric, stat, policy) in specs.items():
        name = ctx.unique_name(f"sim2real-pctfloor-{key}-")
        cw.put_metric_alarm(
            AlarmName=name, Namespace=namespace, MetricName=metric, ExtendedStatistic=stat,
            Unit="Milliseconds", Period=60, EvaluationPeriods=1, DatapointsToAlarm=1,
            Threshold=_THRESHOLD, ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="missing", EvaluateLowSampleCountPercentile=policy,
            ActionsEnabled=False, AlarmDescription=f"sim2real pct floor {key}",
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))
        names[key] = name

    # Data already exists when the alarms are created, so an alarm that evaluates may have fired by
    # its first read; only the withheld ones are pinned to INSUFFICIENT_DATA from the start.
    withheld = ("p90-99-ignore", "p99-200-ignore")
    for key, name in names.items():
        a = _describe(cw, name)
        assert a.get("EvaluateLowSampleCountPercentile") == specs[key][2], (
            f"{key!r} read back EvaluateLowSampleCountPercentile="
            f"{a.get('EvaluateLowSampleCountPercentile')!r}, expected {specs[key][2]!r}"
        )
        assert a.get("ExtendedStatistic") == specs[key][1], (
            f"{key!r} read back ExtendedStatistic={a.get('ExtendedStatistic')!r}"
        )
        allowed = ("INSUFFICIENT_DATA",) if key in withheld else ("INSUFFICIENT_DATA", "ALARM")
        assert a["StateValue"] in allowed, f"{key!r} started in {a['StateValue']!r}"
    baselines = {k: _describe(cw, names[k]).get("StateReason") for k in withheld}

    # --- beat 1: the controls, including the exact boundary, evaluate -------------------------- #
    controls = {
        "p90-100-ignore": 100.0, "p90-99-evaluate": 99.0, "p99-200-evaluate": 200.0,
    }
    fired = _poll_until(
        lambda: {k: _describe(cw, names[k]) for k in controls},
        lambda d: all(a["StateValue"] == "ALARM" for a in d.values()),
        timeout_s=420.0, interval_s=15.0, on_iteration=_tick,
        description=(
            f"the controls {sorted(controls)!r} reached ALARM over a constant {_VALUE} series"
        ),
    )
    for key, expected_n in controls.items():
        srd = json.loads(fired[key]["StateReasonData"])
        evaluated = srd.get("evaluatedDatapoints") or []
        assert srd.get("statistic") == specs[key][1], (
            f"{key!r} StateReasonData statistic={srd.get('statistic')!r}, expected {specs[key][1]!r}"
        )
        assert len(evaluated) == 1 and evaluated[0].get("sampleCount") == expected_n, (
            f"{key!r} fired over evaluatedDatapoints {evaluated!r}; expected one datapoint with "
            f"sampleCount {expected_n} -- exactly what this check publishes per period"
        )
        assert evaluated[0].get("value") == _VALUE, (
            f"{key!r} evaluated value {evaluated[0].get('value')!r}; every sample is {_VALUE}"
        )

    # --- beat 2: below the floor, 'ignore' withholds ------------------------------------------- #
    readings = {k: [] for k in withheld}
    t_end = time.monotonic() + _HOLD_S
    while True:
        _tick()
        for k in withheld:
            readings[k].append(_describe(cw, names[k]))
        if time.monotonic() >= t_end:
            break
        time.sleep(20.0)
    for k in withheld:
        states = [r["StateValue"] for r in readings[k]]
        assert set(states) == {"INSUFFICIENT_DATA"}, (
            f"{k!r} moved during the {_HOLD_S:.0f}s hold after the controls fired: {states!r}. Its "
            f"period holds {_SAMPLES[specs[k][0]]:.0f} samples, below the documented 10/(1-p) "
            f"floor, so 'ignore' must leave the state alone"
        )
        reasons = {r.get("StateReason") for r in readings[k]}
        assert reasons == {baselines[k]}, (
            f"{k!r} StateReason moved from {baselines[k]!r} to {sorted(reasons)!r}"
        )
        alarm_items = [i for i in _state_updates(cw, names[k]) if _new_state(i) == "ALARM"]
        assert alarm_items == [], f"{k!r} history records ALARM transitions {alarm_items!r}"

    # --- beat 3: the percentile the alarm withholds is computable on the query path ----------- #
    end = datetime.now(timezone.utc) + timedelta(minutes=1)
    start = end - timedelta(minutes=20)
    res = cw.get_metric_data(
        MetricDataQueries=[
            {"Id": "p", "MetricStat": {"Metric": {"Namespace": namespace, "MetricName": "P99Below"},
                                       "Period": 60, "Stat": "p99"}},
            {"Id": "n", "MetricStat": {"Metric": {"Namespace": namespace, "MetricName": "P99Below"},
                                       "Period": 60, "Stat": "SampleCount"}},
        ],
        StartTime=start, EndTime=end,
    )["MetricDataResults"]
    by_id = {r["Id"]: r for r in res}
    assert by_id["p"]["StatusCode"] == "Complete" and by_id["p"]["Values"], (
        f"GetMetricData p99 on the 200-sample series returned {by_id['p']!r}; the value the alarm "
        f"withholds must still be computable"
    )
    assert all(abs(v - _VALUE) < 1e-6 for v in by_id["p"]["Values"]), (
        f"GetMetricData p99 returned {by_id['p']['Values']!r}; every sample is {_VALUE}"
    )
    assert by_id["n"]["Values"] and set(by_id["n"]["Values"]) == {200.0}, (
        f"GetMetricData SampleCount returned {by_id['n']['Values']!r}; expected 200.0 per period"
    )


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
