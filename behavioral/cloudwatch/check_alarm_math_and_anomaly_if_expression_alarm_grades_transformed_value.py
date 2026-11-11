"""alarm-math-and-anomaly-if-expression-alarm-grades-transformed-value."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alarm-math-and-anomaly-if-expression-alarm-grades-transformed-value"
GROUP = "metric-math"
SERVICES = ["cloudwatch"]

_EXPRESSION = "IF(m1 > 100, 0, 1000)"
_THRESHOLD = 500.0
#: Leg A: raw 700 is ABOVE the threshold, IF maps it to 0 -> OK.
_RAW_HIGH, _MAPPED_HIGH = 700.0, 0.0
#: Leg B: raw 50 is BELOW the threshold, IF maps it to 1000 -> ALARM.
_RAW_LOW, _MAPPED_LOW = 50.0, 1000.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Create-alarm-on-metric-math-expression.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An alarm over IF(m1 > 100, 0, 1000) grades the IF output: raw 700 stays OK and raw 50 reaches
    ALARM from OK, and each cited value matches GetMetricData for the same Metrics array.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/using-metric-math.html
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehavMathIf")
    alarm_name = ctx.unique_name("sim2real-behav-mathif-")
    raw = [_RAW_HIGH]

    def _publish() -> None:
        stamp = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        cw.put_metric_data(Namespace=namespace, MetricData=[
            {"MetricName": "Load", "Timestamp": stamp, "Value": raw[0], "Unit": "Count"}])

    # Minimum, so leg B's first 50 decides its minute at once even when that minute already holds
    # leg A's 700s; with Maximum, leg B would wait for the next minute boundary.
    metrics = [
        {"Id": "m1", "MetricStat": {"Metric": {"Namespace": namespace, "MetricName": "Load"},
                                    "Period": 60, "Stat": "Minimum"}, "ReturnData": False},
        {"Id": "e1", "Expression": _EXPRESSION, "Label": "Inverted", "ReturnData": True},
    ]

    _publish()
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Metrics=metrics,
        Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold",
        EvaluationPeriods=1,
        DatapointsToAlarm=1,
        TreatMissingData="missing",
        ActionsEnabled=False,
        AlarmDescription="sim2real-behav: IF() inside an alarm expression",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    readback = {q["Id"]: q for q in _describe(cw, alarm_name)["Metrics"]}
    assert readback["e1"]["Expression"] == _EXPRESSION, (
        f"the alarm stored the expression {readback['e1'].get('Expression')!r}, expected "
        f"{_EXPRESSION!r}"
    )

    # --- leg A: raw 700 (above 500) is mapped to 0 -> OK ---------------------------------------- #
    a = _poll_until(
        lambda: _describe(cw, alarm_name),
        lambda al: al["StateValue"] != "INSUFFICIENT_DATA",
        timeout_s=_budget(ctx, 420.0, 20.0), interval_s=2.0, on_iteration=_publish,
        description=f"alarm {alarm_name!r} left INSUFFICIENT_DATA on its first real evaluation",
    )
    assert a["StateValue"] == "OK", (
        f"m1={_RAW_HIGH} makes {_EXPRESSION} evaluate to {_MAPPED_HIGH}, below {_THRESHOLD}, so "
        f"the alarm must be OK; it reached {a['StateValue']!r} ({a['StateReason']!r}) -- grading "
        f"the raw metric instead of the IF output lands here"
    )
    ts_a, v_a = _evaluated(a)
    assert v_a == _MAPPED_HIGH, f"leg A cites {v_a!r}; the IF output is {_MAPPED_HIGH}"
    _cross_check(cw, metrics, ts_a, v_a, _RAW_HIGH)
    early = [i for i in _state_updates(cw, alarm_name) if _new_state(i) == "ALARM"]
    assert early == [], (
        f"history records ALARM while the raw metric breached but the IF output did not: "
        f"{[i['HistorySummary'] for i in early]!r}"
    )

    # --- leg B (positive control): raw 50 (below 500) is mapped to 1000 -> ALARM ---------------- #
    raw[0] = _RAW_LOW
    _publish()
    b = _poll_until(
        lambda: _describe(cw, alarm_name),
        lambda al: al["StateValue"] == "ALARM",
        timeout_s=_budget(ctx, 420.0, 10.0), interval_s=2.0, on_iteration=_publish,
        description=(f"alarm {alarm_name!r} fired once m1={_RAW_LOW} made the IF output "
                     f"{_MAPPED_LOW}"),
    )
    ts_b, v_b = _evaluated(b)
    assert v_b == _MAPPED_LOW, f"leg B cites {v_b!r}; the IF output is {_MAPPED_LOW}"
    _cross_check(cw, metrics, ts_b, v_b, _RAW_LOW)

    updates = _poll_until(
        lambda: [i for i in _state_updates(cw, alarm_name) if _new_state(i) == "ALARM"],
        lambda items: len(items) >= 1,
        timeout_s=_budget(ctx, 180.0), interval_s=2.0,
        description=f"a StateUpdate history item recording the ALARM of {alarm_name!r}",
    )
    entry = json.loads(updates[-1]["HistoryData"])
    assert entry["oldState"]["stateValue"] == "OK", (
        f"the ALARM transition came from {entry['oldState']['stateValue']!r}, expected leg A's OK"
    )
    hist = [float(v) for v in entry["newState"]["stateReasonData"]["recentDatapoints"]]
    assert hist == [_MAPPED_LOW], (
        f"history's recentDatapoints are {hist!r}; expected the IF output [{_MAPPED_LOW}], not "
        f"the raw [{_RAW_LOW}]"
    )


def _budget(ctx, cap_s, reserve_s=5.0):
    """A wait's cap, cut to the runner's remaining time so the check fails with its own message."""
    left = ctx.time_left()
    return max(1.0, min(cap_s, (cap_s if left is None else left) - reserve_s))


def _evaluated(alarm: dict) -> tuple[datetime, float]:
    srd = json.loads(alarm["StateReasonData"])
    pts = srd["evaluatedDatapoints"]
    assert len(pts) == 1, f"EvaluationPeriods=1 must grade one datapoint; got {pts!r}"
    ts = datetime.strptime(pts[0]["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z")
    return ts, float(pts[0]["value"])


def _cross_check(cw, metrics, ts: datetime, cited: float, raw_value: float) -> None:
    queries = [dict(q, ReturnData=True) for q in metrics]
    res = cw.get_metric_data(MetricDataQueries=queries, StartTime=ts,
                             EndTime=ts + timedelta(seconds=60), ScanBy="TimestampAscending")
    by_id = {r["Id"]: r for r in res["MetricDataResults"]}

    def _at(qid: str) -> float:
        r = by_id[qid]
        hits = [v for t, v in zip(r["Timestamps"], r["Values"]) if t == ts]
        assert len(hits) == 1, (
            f"GetMetricData has no single {qid!r} value at {ts.isoformat()}: "
            f"{[t.isoformat() for t in r['Timestamps']]!r}"
        )
        return float(hits[0])

    assert _at("e1") == cited, (
        f"GetMetricData computes {_EXPRESSION} = {_at('e1')!r} at {ts.isoformat()}, but the alarm "
        f"cited {cited!r} for that timestamp"
    )
    assert _at("m1") == raw_value, (
        f"raw m1 at {ts.isoformat()} is {_at('m1')!r}, expected {raw_value}"
    )


def _describe(cw, alarm_name):
    for page in cw.get_paginator("describe_alarms").paginate(
            AlarmNames=[alarm_name], AlarmTypes=["MetricAlarm"]):
        for alarm in page.get("MetricAlarms", []):
            if alarm["AlarmName"] == alarm_name:
                return alarm
    raise AssertionError(f"alarm {alarm_name!r} is not present in DescribeAlarms")


def _state_updates(cw, alarm_name):
    items = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
            AlarmName=alarm_name, HistoryItemType="StateUpdate", ScanBy="TimestampAscending"):
        items.extend(page.get("AlarmHistoryItems", []))
    return items


def _new_state(item) -> str:
    return json.loads(item["HistoryData"]).get("newState", {}).get("stateValue", "")


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, on_iteration=None):
    """Poll probe() until predicate(result); FAIL on exhaustion, never skip."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            last = probe()
        except ClientError as exc:
            last = exc.response["Error"]
        else:
            if predicate(last):
                return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} did not happen within {timeout_s}s; "
                                 f"last observation {last!r}")
        if on_iteration is not None:
            on_iteration()
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
