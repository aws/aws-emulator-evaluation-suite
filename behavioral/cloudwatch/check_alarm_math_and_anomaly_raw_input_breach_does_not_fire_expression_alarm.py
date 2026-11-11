"""alarm-math-and-anomaly-raw-input-breach-does-not-fire-expression-alarm."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "alarm-math-and-anomaly-raw-input-breach-does-not-fire-expression-alarm"
GROUP = "metric-math"
SERVICES = ["cloudwatch"]

_THRESHOLD = 50.0
_REQUESTS = 400.0
#: Leg A: BOTH raw inputs (80 and 400) are above the threshold of 50, the expression is 20.
_ERRORS_QUIET = 80.0
_RATE_QUIET = 20.0
#: Leg B: the expression crosses (300/400*100 == 75).
_ERRORS_LOUD = 300.0
_RATE_LOUD = 75.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Create-alarm-on-metric-math-expression.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A math alarm whose raw inputs are above its threshold stays OK while the expression is below
    it, then reaches ALARM from OK once the expression crosses; both cited values match GetMetricData
    for the same Metrics array.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Create-alarm-on-metric-math-expression.html
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealBehavMathRaw")
    alarm_name = ctx.unique_name("sim2real-behav-mathraw-")
    errors_value = [_ERRORS_QUIET]

    def _publish() -> None:
        stamp = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {"MetricName": "Errors", "Timestamp": stamp, "Value": errors_value[0],
                 "Unit": "Count"},
                {"MetricName": "Requests", "Timestamp": stamp, "Value": _REQUESTS,
                 "Unit": "Count"},
            ],
        )

    metrics = [
        {"Id": "m1", "MetricStat": {"Metric": {"Namespace": namespace, "MetricName": "Errors"},
                                    "Period": 60, "Stat": "Maximum"}, "ReturnData": False},
        {"Id": "m2", "MetricStat": {"Metric": {"Namespace": namespace, "MetricName": "Requests"},
                                    "Period": 60, "Stat": "Maximum"}, "ReturnData": False},
        {"Id": "e1", "Expression": "(m1/m2)*100", "Label": "ErrorRate", "ReturnData": True},
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
        AlarmDescription="sim2real-behav: raw inputs breach, expression does not",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    # --- leg A: raw inputs 80 and 400 are above 50; the expression is 20 -> OK ------------------ #
    quiet = _poll_until(
        lambda: _describe(cw, alarm_name),
        lambda a: a["StateValue"] != "INSUFFICIENT_DATA",
        timeout_s=420.0, interval_s=15.0, on_iteration=_publish,
        description=f"alarm {alarm_name!r} left INSUFFICIENT_DATA on its first real evaluation",
    )
    assert quiet["StateValue"] == "OK", (
        f"with errors={_ERRORS_QUIET} and requests={_REQUESTS} (both above the threshold "
        f"{_THRESHOLD}) the expression (m1/m2)*100 is {_RATE_QUIET}, so the alarm must be OK; it "
        f"reached {quiet['StateValue']!r} with reason {quiet['StateReason']!r} -- an evaluator "
        f"grading a raw input instead of the expression lands here"
    )
    ts_quiet, v_quiet = _evaluated(quiet)
    assert abs(v_quiet - _RATE_QUIET) < 1e-6, (
        f"the OK verdict cites the value {v_quiet!r}; expected the computed {_RATE_QUIET}. "
        f"{_ERRORS_QUIET} or {_REQUESTS} here means a raw input was evaluated"
    )
    _cross_check(cw, metrics, ts_quiet, v_quiet, _ERRORS_QUIET)

    # effect-absent: no ALARM was ever recorded while only the raw inputs breached
    fired_early = [i for i in _state_updates(cw, alarm_name) if _new_state(i) == "ALARM"]
    assert fired_early == [], (
        f"the alarm history records an ALARM transition during leg A, when only the raw inputs "
        f"were above the threshold: {[i['HistorySummary'] for i in fired_early]!r}"
    )

    # --- leg B (positive control): the expression crosses to 75 -> ALARM ------------------------ #
    errors_value[0] = _ERRORS_LOUD
    _publish()
    loud = _poll_until(
        lambda: _describe(cw, alarm_name),
        lambda a: a["StateValue"] == "ALARM",
        timeout_s=420.0, interval_s=15.0, on_iteration=_publish,
        description=(f"alarm {alarm_name!r} fired once the expression reached {_RATE_LOUD}; no "
                     f"set_alarm_state call exists in this file"),
    )
    ts_loud, v_loud = _evaluated(loud)
    assert abs(v_loud - _RATE_LOUD) < 1e-6, (
        f"the ALARM verdict cites the value {v_loud!r}; expected the computed {_RATE_LOUD}"
    )
    _cross_check(cw, metrics, ts_loud, v_loud, _ERRORS_LOUD)

    updates = _poll_until(
        lambda: [i for i in _state_updates(cw, alarm_name) if _new_state(i) == "ALARM"],
        lambda items: len(items) >= 1,
        timeout_s=180.0, interval_s=5.0,
        description=f"a StateUpdate history item recording the ALARM transition of {alarm_name!r}",
    )
    entry = json.loads(updates[-1]["HistoryData"])
    assert entry["oldState"]["stateValue"] == "OK", (
        f"the ALARM transition in history came from {entry['oldState']['stateValue']!r}; it must "
        f"come from leg A's OK, which is what makes the two legs one alarm's history"
    )
    hist_values = entry["newState"]["stateReasonData"]["recentDatapoints"]
    assert [round(float(v), 6) for v in hist_values] == [_RATE_LOUD], (
        f"the history entry's recentDatapoints are {hist_values!r}; expected [{_RATE_LOUD}]"
    )


def _evaluated(alarm: dict) -> tuple[datetime, float]:
    """(timestamp, value) of the single datapoint the evaluator says it graded."""
    srd = json.loads(alarm["StateReasonData"])
    pts = srd["evaluatedDatapoints"]
    assert len(pts) == 1, (
        f"EvaluationPeriods=1 must grade exactly one datapoint; StateReasonData cites {pts!r}"
    )
    ts = datetime.strptime(pts[0]["timestamp"], "%Y-%m-%dT%H:%M:%S.%f%z")
    return ts, float(pts[0]["value"])


def _cross_check(cw, metrics, ts: datetime, cited: float, raw_errors: float) -> None:
    """GetMetricData over the SAME Metrics array must compute the value the evaluator cited."""
    queries = [dict(q, ReturnData=True) for q in metrics]
    res = cw.get_metric_data(MetricDataQueries=queries, StartTime=ts,
                             EndTime=ts + timedelta(seconds=60), ScanBy="TimestampAscending")
    by_id = {r["Id"]: r for r in res["MetricDataResults"]}

    def _at(qid: str) -> float:
        r = by_id[qid]
        hits = [v for t, v in zip(r["Timestamps"], r["Values"]) if t == ts]
        assert len(hits) == 1, (
            f"GetMetricData returned no single {qid!r} value at the evaluated timestamp "
            f"{ts.isoformat()}: timestamps {[t.isoformat() for t in r['Timestamps']]!r}"
        )
        return float(hits[0])

    computed = _at("e1")
    assert abs(computed - cited) < 1e-6, (
        f"GetMetricData computes (m1/m2)*100 = {computed!r} at {ts.isoformat()}, but the alarm "
        f"cited {cited!r} for that same timestamp -- the evaluator and the query path disagree"
    )
    assert abs(_at("m1") - raw_errors) < 1e-6 and abs(_at("m2") - _REQUESTS) < 1e-6, (
        f"the raw inputs at {ts.isoformat()} read back m1={_at('m1')!r} m2={_at('m2')!r}; "
        f"expected {raw_errors} and {_REQUESTS}"
    )
    assert abs(cited - raw_errors) > 1e-6 and abs(cited - _REQUESTS) > 1e-6, (
        f"the cited value {cited!r} equals a raw input; the expression was not what was graded"
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
