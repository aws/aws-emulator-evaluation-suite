"""alarm-unit-and-percentile-traps-omitted-unit-matches-any-unit-and-unitless-is-none."""
from __future__ import annotations

# On real AWS, a datum published with no Unit reads back from
# GetMetricStatistics(Unit='None') tagged 'None' and is invisible to Unit='Count'. An alarm with
# Unit omitted and one with Unit='None' both reached ALARM over it; Unit='Count' stayed
# INSUFFICIENT_DATA ('Unchecked: Initial alarm creation').

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-unit-and-percentile-traps-omitted-unit-matches-any-unit-and-unitless-is-none"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_THRESHOLD = 10.0
_VALUE = 500.0
#: metric name -> the Unit it is published with (None = the Unit key is left out entirely).
_PUBLISHED = {
    "PctMetric": "Percent",
    "RateMetric": "Bytes/Second",
    "CountMetric": "Count",
    "BareMetric": None,
}
_HOLD_S = 120.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics",
      "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An alarm with no Unit evaluates whatever unit was published; a unitless datum IS 'None'.

    A Unit='Count' alarm on the unitless series holds INSUFFICIENT_DATA while the others alarm."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealUnitAnyNs")

    def _publish() -> None:
        now = datetime.now(timezone.utc)
        data = []
        for metric, unit in _PUBLISHED.items():
            datum = {"MetricName": metric, "Timestamp": now, "Value": _VALUE}
            if unit is not None:
                datum["Unit"] = unit
            data.append(datum)
        cw.put_metric_data(Namespace=namespace, MetricData=data)

    def _create(name: str, metric: str, unit):
        kwargs = dict(
            AlarmName=name, Namespace=namespace, MetricName=metric, Statistic="Maximum",
            Period=60, EvaluationPeriods=1, DatapointsToAlarm=1, Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanThreshold", TreatMissingData="missing",
            ActionsEnabled=False, AlarmDescription=f"sim2real unit-any {metric} Unit={unit!r}",
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
        if unit is not None:
            kwargs["Unit"] = unit
        cw.put_metric_alarm(**kwargs)

    _publish()
    controls = {}
    for metric in _PUBLISHED:
        name = ctx.unique_name(f"sim2real-unitany-omit-{metric.lower()}-")
        _create(name, metric, None)
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))
        controls[f"omit/{metric}"] = name
    none_name = ctx.unique_name("sim2real-unitany-none-")
    _create(none_name, "BareMetric", "None")
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[none_name]))
    controls["None/BareMetric"] = none_name
    count_name = ctx.unique_name("sim2real-unitany-count-")
    _create(count_name, "BareMetric", "Count")
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[count_name]))

    count_alarm = _describe(cw, count_name)
    assert count_alarm.get("Unit") == "Count", (
        f"the Count-pinned alarm read back Unit={count_alarm.get('Unit')!r}"
    )
    none_alarm = _describe(cw, none_name)
    assert none_alarm.get("Unit") == "None", (
        f"the None-pinned alarm read back Unit={none_alarm.get('Unit')!r}, expected the literal 'None'"
    )
    assert count_alarm["StateValue"] == "INSUFFICIENT_DATA", (
        f"the Count-pinned alarm started in {count_alarm['StateValue']!r}"
    )
    baseline_reason = count_alarm.get("StateReason")

    # --- beat 1: every omitted-Unit alarm fires, whatever unit its metric carries --------------- #
    fired = _poll_until(
        lambda: {k: _describe(cw, n) for k, n in controls.items()},
        lambda d: all(a["StateValue"] == "ALARM" for a in d.values()),
        timeout_s=420.0, interval_s=15.0, on_iteration=_publish,
        description=(
            f"all five controls ({sorted(controls)!r}) reached ALARM over {_VALUE} published under "
            f"units {sorted(str(u) for u in _PUBLISHED.values())!r}"
        ),
    )
    for key, alarm in fired.items():
        srd = json.loads(alarm["StateReasonData"])
        assert srd.get("recentDatapoints") == [_VALUE], (
            f"control {key!r} fired over recentDatapoints {srd.get('recentDatapoints')!r}, "
            f"expected [{_VALUE!r}]"
        )

    # --- beat 2: the Count-pinned alarm over the unitless series stays starved ----------------- #
    readings = []
    t_end = time.monotonic() + _HOLD_S
    while True:
        _publish()
        readings.append(_describe(cw, count_name))
        if time.monotonic() >= t_end:
            break
        time.sleep(20.0)
    states = [r["StateValue"] for r in readings]
    assert set(states) == {"INSUFFICIENT_DATA"}, (
        f"the Unit='Count' alarm over a metric published WITHOUT a unit moved during the hold: "
        f"{states!r}. A unitless datum is stored under the literal unit 'None', not as a wildcard"
    )
    reasons = {r.get("StateReason") for r in readings}
    assert reasons == {baseline_reason}, (
        f"the Unit='Count' alarm's StateReason moved from {baseline_reason!r} to {sorted(reasons)!r}"
    )
    alarm_items = [i for i in _state_updates(cw, count_name) if _new_state(i) == "ALARM"]
    assert alarm_items == [], f"the Unit='Count' alarm's history records ALARM items {alarm_items!r}"

    # --- beat 3: the read path stores the unitless datum as 'None' ----------------------------- #
    end = datetime.now(timezone.utc) + timedelta(minutes=1)
    start = end - timedelta(minutes=20)
    as_none = cw.get_metric_statistics(
        Namespace=namespace, MetricName="BareMetric", StartTime=start, EndTime=end, Period=60,
        Statistics=["Maximum"], Unit="None",
    )["Datapoints"]
    assert as_none and all(d["Unit"] == "None" and d["Maximum"] == _VALUE for d in as_none), (
        f"GetMetricStatistics(Unit='None') on the unitless metric returned {as_none!r}; expected "
        f"{_VALUE} tagged 'None'"
    )
    as_count = cw.get_metric_statistics(
        Namespace=namespace, MetricName="BareMetric", StartTime=start, EndTime=end, Period=60,
        Statistics=["Maximum"], Unit="Count",
    )["Datapoints"]
    assert as_count == [], (
        f"GetMetricStatistics(Unit='Count') on the unitless metric returned {as_count!r}; expected none"
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
