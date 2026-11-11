"""alarm-unit-and-percentile-traps-alarm-dimensions-are-an-unordered-exact-set."""
from __future__ import annotations

# An alarm's dimensions match a series as an exact, unordered set: an alarm created with
# Dimensions [B, A] evaluates a series published with [A, B], and DescribeAlarmsForMetric with
# [A, B] or [B, A] returns it, while [A], [A, B, C] or no dimensions do not. Custom metrics do not
# roll up across dimensions, so an alarm on [A] alone stays INSUFFICIENT_DATA and GetMetricData
# on [A] returns no values.

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-unit-and-percentile-traps-alarm-dimensions-are-an-unordered-exact-set"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_THRESHOLD = 10.0
_VALUE = 500.0
_A = {"Name": "Service", "Value": "checkout"}
_B = {"Name": "Stage", "Value": "prod"}
_C = {"Name": "Zone", "Value": "z1"}
_HOLD_S = 120.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics",
      "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An alarm's dimensions are an unordered EXACT set: order never matters, subset and superset
    never match -- for DescribeAlarmsForMetric and for the evaluator alike."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealDimSetNs")
    metric = "Errors"

    def _publish() -> None:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": metric, "Dimensions": [_A, _B],
                         "Timestamp": datetime.now(timezone.utc), "Value": _VALUE,
                         "Unit": "Count"}],
        )

    _publish()
    dims = {"full": [_B, _A], "sub": [_A], "super": [_A, _B, _C]}
    names = {}
    for key, d in dims.items():
        name = ctx.unique_name(f"sim2real-dimset-{key}-")
        cw.put_metric_alarm(
            AlarmName=name, Namespace=namespace, MetricName=metric, Dimensions=d,
            Statistic="Maximum", Period=60, EvaluationPeriods=1, DatapointsToAlarm=1,
            Threshold=_THRESHOLD, ComparisonOperator="GreaterThanThreshold",
            TreatMissingData="missing", ActionsEnabled=False,
            AlarmDescription=f"sim2real dimension set {key}",
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))
        names[key] = name

    for key, name in names.items():
        a = _describe(cw, name)
        got = {(x["Name"], x["Value"]) for x in a.get("Dimensions", [])}
        want = {(x["Name"], x["Value"]) for x in dims[key]}
        assert got == want, f"{key!r} read back dimensions {sorted(got)!r}, expected {sorted(want)!r}"

    # --- beat 1: DescribeAlarmsForMetric matches the exact set, in any order ------------------- #
    def _lookup(d):
        kwargs = dict(Namespace=namespace, MetricName=metric)
        if d is not None:
            kwargs["Dimensions"] = d
        return {a["AlarmName"] for a in cw.describe_alarms_for_metric(**kwargs)["MetricAlarms"]}

    cases = [
        ("[A,B] (publish order)", [_A, _B], {names["full"]}),
        ("[B,A] (alarm order)", [_B, _A], {names["full"]}),
        ("[A] (subset)", [_A], {names["sub"]}),
        ("[A,B,C] (superset)", [_A, _B, _C], {names["super"]}),
        ("no dimensions", None, set()),
    ]
    for label, d, expected in cases:
        got = _lookup(d)
        assert got == expected, (
            f"DescribeAlarmsForMetric with {label} returned {sorted(got)!r}, expected "
            f"{sorted(expected)!r}; dimension matching is by exact unordered set"
        )

    baselines = {k: _describe(cw, names[k]).get("StateReason") for k in ("sub", "super")}

    # --- beat 2: the reversed-order alarm evaluates the published series ----------------------- #
    fired = _poll_until(
        lambda: _describe(cw, names["full"]),
        lambda a: a["StateValue"] == "ALARM",
        timeout_s=420.0, interval_s=15.0, on_iteration=_publish,
        description=(
            f"the alarm created with dimensions [B, A] reached ALARM over the series published "
            f"with [A, B]"
        ),
    )
    window = json.loads(fired["StateReasonData"]).get("recentDatapoints")
    assert window == [_VALUE], f"the [B, A] alarm fired over {window!r}, expected [{_VALUE!r}]"

    # --- beat 3: subset and superset alarms never see the [A, B] series ------------------------ #
    readings = {k: [] for k in baselines}
    t_end = time.monotonic() + _HOLD_S
    while True:
        _publish()
        for k in baselines:
            readings[k].append(_describe(cw, names[k]))
        if time.monotonic() >= t_end:
            break
        time.sleep(20.0)
    for k in baselines:
        states = [r["StateValue"] for r in readings[k]]
        assert set(states) == {"INSUFFICIENT_DATA"}, (
            f"the {k!r} alarm (dimensions {dims[k]!r}) moved during the hold: {states!r}; only the "
            f"[A, B] series exists, and a custom metric does not roll up across dimensions"
        )
        reasons = {r.get("StateReason") for r in readings[k]}
        assert reasons == {baselines[k]}, (
            f"the {k!r} alarm's StateReason moved from {baselines[k]!r} to {sorted(reasons)!r}"
        )
        alarm_items = [i for i in _state_updates(cw, names[k]) if _new_state(i) == "ALARM"]
        assert alarm_items == [], f"the {k!r} alarm's history records {alarm_items!r}"

    # --- beat 4: the query path draws the same line -------------------------------------------- #
    end = datetime.now(timezone.utc) + timedelta(minutes=1)
    start = end - timedelta(minutes=20)
    res = {r["Id"]: r for r in cw.get_metric_data(
        MetricDataQueries=[
            {"Id": qid, "MetricStat": {
                "Metric": {"Namespace": namespace, "MetricName": metric, "Dimensions": d},
                "Period": 60, "Stat": "Maximum"}}
            for qid, d in (("rev", [_B, _A]), ("sub", [_A]), ("sup", [_A, _B, _C]))
        ],
        StartTime=start, EndTime=end,
    )["MetricDataResults"]}
    assert res["rev"]["Values"] and set(res["rev"]["Values"]) == {_VALUE}, (
        f"GetMetricData with dimensions [B, A] returned {res['rev']!r}; expected {_VALUE}"
    )
    for qid in ("sub", "sup"):
        assert res[qid]["StatusCode"] == "Complete" and res[qid]["Values"] == [], (
            f"GetMetricData with the {qid!r} dimension set returned {res[qid]!r}; expected no values"
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
