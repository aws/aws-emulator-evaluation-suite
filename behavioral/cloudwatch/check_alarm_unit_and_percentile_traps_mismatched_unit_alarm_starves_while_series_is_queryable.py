"""alarm-unit-and-percentile-traps-mismatched-unit-alarm-starves-while-series-is-queryable."""
from __future__ import annotations

# An alarm's Unit filters the series it evaluates. Over a Milliseconds series, a Maximum alarm
# with Unit='Milliseconds' and one with Unit omitted both reach ALARM; a Unit='Seconds' twin stays
# INSUFFICIENT_DATA ('Unchecked: Initial alarm creation') while GetMetricData (no unit) and
# GetMetricStatistics(Unit='Milliseconds') return the value and the Unit='Seconds' queries return
# nothing.

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-unit-and-percentile-traps-mismatched-unit-alarm-starves-while-series-is-queryable"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_THRESHOLD = 10.0
_VALUE = 500.0
_PUBLISHED_UNIT = "Milliseconds"
_WRONG_UNIT = "Seconds"
_HOLD_S = 120.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics",
      "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An alarm whose Unit differs from the published unit never sees the data that IS there.

    Matching-Unit and no-Unit alarms fire while the Unit='Seconds' alarm holds and the series reads back."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealUnitTrapNs")
    metric = "RequestLatency"
    names = {
        "match": ctx.unique_name("sim2real-unittrap-match-"),
        "omit": ctx.unique_name("sim2real-unittrap-omit-"),
        "wrong": ctx.unique_name("sim2real-unittrap-wrong-"),
    }
    units = {"match": _PUBLISHED_UNIT, "omit": None, "wrong": _WRONG_UNIT}

    def _publish() -> None:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{
                "MetricName": metric,
                "Timestamp": datetime.now(timezone.utc),
                "Value": _VALUE,
                "Unit": _PUBLISHED_UNIT,
            }],
        )

    _publish()
    for key, name in names.items():
        kwargs = dict(
            AlarmName=name, Namespace=namespace, MetricName=metric, Statistic="Maximum",
            Period=60, EvaluationPeriods=1, DatapointsToAlarm=1, Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanThreshold", TreatMissingData="missing",
            ActionsEnabled=False, AlarmDescription=f"sim2real unit trap Unit={units[key]!r}",
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
        if units[key] is not None:
            kwargs["Unit"] = units[key]
        cw.put_metric_alarm(**kwargs)
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))

    described = {k: _describe(cw, n) for k, n in names.items()}
    assert described["match"].get("Unit") == _PUBLISHED_UNIT, (
        f"matching alarm read back Unit={described['match'].get('Unit')!r}, expected {_PUBLISHED_UNIT!r}"
    )
    assert "Unit" not in described["omit"], (
        f"the no-Unit alarm read back Unit={described['omit'].get('Unit')!r}; it was created without one"
    )
    assert described["wrong"].get("Unit") == _WRONG_UNIT, (
        f"mismatched alarm read back Unit={described['wrong'].get('Unit')!r}, expected {_WRONG_UNIT!r}"
    )
    for key, alarm in described.items():
        assert alarm["StateValue"] == "INSUFFICIENT_DATA", (
            f"the {key!r} alarm started in {alarm['StateValue']!r}, expected INSUFFICIENT_DATA"
        )
    baseline_reason = described["wrong"].get("StateReason")

    # --- beat 1: both controls fire ------------------------------------------------------------ #
    fired = _poll_until(
        lambda: {k: _describe(cw, names[k]) for k in ("match", "omit")},
        lambda d: all(a["StateValue"] == "ALARM" for a in d.values()),
        timeout_s=420.0, interval_s=15.0, on_iteration=_publish,
        description=(
            f"both the Unit={_PUBLISHED_UNIT!r} alarm and the no-Unit alarm reached ALARM over a "
            f"{_PUBLISHED_UNIT} series of {_VALUE} against threshold {_THRESHOLD}"
        ),
    )
    for key, alarm in fired.items():
        srd = json.loads(alarm["StateReasonData"])
        assert srd.get("recentDatapoints") == [_VALUE], (
            f"the {key!r} control fired over recentDatapoints {srd.get('recentDatapoints')!r}, "
            f"expected [{_VALUE!r}] -- the only value this check publishes"
        )
        assert srd.get("statistic") == "Maximum" and srd.get("period") == 60, (
            f"the {key!r} control's StateReasonData names statistic={srd.get('statistic')!r} "
            f"period={srd.get('period')!r}, expected Maximum / 60"
        )

    # --- beat 2: the mismatched alarm stays starved across a hold after the controls fired ----- #
    readings = []
    t_end = time.monotonic() + _HOLD_S
    while True:
        _publish()
        readings.append(_describe(cw, names["wrong"]))
        if time.monotonic() >= t_end:
            break
        time.sleep(20.0)
    states = [r["StateValue"] for r in readings]
    assert set(states) == {"INSUFFICIENT_DATA"}, (
        f"the Unit={_WRONG_UNIT!r} alarm moved during the {_HOLD_S:.0f}s hold after both controls "
        f"fired: {states!r}. Every datapoint carries Unit={_PUBLISHED_UNIT!r}, so it must see none"
    )
    reasons = {r.get("StateReason") for r in readings}
    assert reasons == {baseline_reason}, (
        f"the Unit={_WRONG_UNIT!r} alarm's StateReason moved from {baseline_reason!r} to "
        f"{sorted(x for x in reasons if x != baseline_reason)!r}; an alarm that never resolves a "
        f"datapoint under its unit has nothing to rewrite it with"
    )
    alarm_items = [i for i in _state_updates(cw, names["wrong"]) if _new_state(i) == "ALARM"]
    assert alarm_items == [], (
        f"the Unit={_WRONG_UNIT!r} alarm's history records ALARM transitions {alarm_items!r}"
    )

    # --- beat 3: the same series is plainly readable on the query path ------------------------- #
    end = datetime.now(timezone.utc) + timedelta(minutes=1)
    start = end - timedelta(minutes=20)

    def _gmd(unit):
        stat = {"Metric": {"Namespace": namespace, "MetricName": metric}, "Period": 60,
                "Stat": "Maximum"}
        if unit is not None:
            stat["Unit"] = unit
        res = cw.get_metric_data(
            MetricDataQueries=[{"Id": "q", "MetricStat": stat}], StartTime=start, EndTime=end
        )["MetricDataResults"][0]
        return res

    unfiltered = _gmd(None)
    assert unfiltered["StatusCode"] == "Complete" and unfiltered["Values"], (
        f"GetMetricData without a unit returned {unfiltered!r}; the series must be readable while "
        f"the mismatched alarm starves, or the starvation proves nothing"
    )
    assert set(unfiltered["Values"]) == {_VALUE}, (
        f"GetMetricData returned values {unfiltered['Values']!r}, expected only {_VALUE!r}"
    )
    wrong_gmd = _gmd(_WRONG_UNIT)
    assert wrong_gmd["StatusCode"] == "Complete" and wrong_gmd["Values"] == [], (
        f"GetMetricData(Unit={_WRONG_UNIT!r}) returned {wrong_gmd!r}; expected Complete with no "
        f"values -- no datapoint was ever published under that unit"
    )
    ms = cw.get_metric_statistics(
        Namespace=namespace, MetricName=metric, StartTime=start, EndTime=end, Period=60,
        Statistics=["Maximum"], Unit=_PUBLISHED_UNIT,
    )["Datapoints"]
    assert ms and all(d["Maximum"] == _VALUE and d["Unit"] == _PUBLISHED_UNIT for d in ms), (
        f"GetMetricStatistics(Unit={_PUBLISHED_UNIT!r}) returned {ms!r}; expected datapoints of "
        f"{_VALUE} tagged {_PUBLISHED_UNIT!r}"
    )
    wrong_gms = cw.get_metric_statistics(
        Namespace=namespace, MetricName=metric, StartTime=start, EndTime=end, Period=60,
        Statistics=["Maximum"], Unit=_WRONG_UNIT,
    )["Datapoints"]
    assert wrong_gms == [], (
        f"GetMetricStatistics(Unit={_WRONG_UNIT!r}) returned {wrong_gms!r}; expected none"
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
