"""alarm-evaluation-engine-metric-math-alarm-evaluates-the-computed-series."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-evaluation-engine-metric-math-alarm-evaluates-the-computed-series"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_PERIOD = 10
_N = 2
_THRESHOLD = 50.0
_PART_LOW = 20.0     # a + b = 40 -> OK
_PART_HIGH = 30.0    # a + b = 60 -> ALARM, while each input alone stays below 50


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "cap:c7", "concern:data-plane", "concern:metrics",
      "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An alarm on the expression a + b > 50 goes OK citing 40.0 and then ALARM citing 60.0, with
    evaluatedDatapoints of only timestamp and value, while an alarm on input a alone (30) stays OK,
    cites only values put into a and never alarms: the evaluator runs the computed series."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealEvalEngineMath")
    expr_alarm = ctx.unique_name("sim2real-eval-engine-expr-")
    part_alarm = ctx.unique_name("sim2real-eval-engine-parta-")

    def stat(i, m):
        return {"Id": i, "ReturnData": False, "MetricStat": {
            "Metric": {"Namespace": namespace, "MetricName": m}, "Period": _PERIOD,
            "Stat": "Maximum"}}

    cw.put_metric_alarm(
        AlarmName=expr_alarm,
        Metrics=[stat("a", "PartA"), stat("b", "PartB"),
                 {"Id": "total", "Expression": "a + b", "Label": "Total", "ReturnData": True}],
        EvaluationPeriods=_N, DatapointsToAlarm=_N, Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold", TreatMissingData="missing", ActionsEnabled=False,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[expr_alarm]))

    low: set[datetime] = set()

    def publish_low():
        now = _now_bucket(_PERIOD)
        for i in range(_N + 1):
            b = now - timedelta(seconds=_PERIOD * i)
            if b not in low:
                _put(cw, namespace, "PartA", b, _PART_LOW)
                _put(cw, namespace, "PartB", b, _PART_LOW)
                low.add(b)

    st = _drive_until(publish_low, lambda: _describe(cw, expr_alarm),
                      lambda a: a["StateValue"] != "INSUFFICIENT_DATA",
                      what="the expression alarm evaluating a + b")
    assert st["StateValue"] == "OK", f"a + b = 40 moved the alarm to {st['StateValue']!r}: {st['StateReason']!r}"
    rd = _words_and_data(_poll_new_state(cw, expr_alarm, "OK")[0], relation="not greater than",
                         value=2 * _PART_LOW, buckets=low, statistic=None, evaluated=1)
    for dp in rd["evaluatedDatapoints"]:
        assert set(dp) == {"timestamp", "value"}, f"expression evaluatedDatapoint fields {sorted(dp)!r}"

    # Single-input control alarm on `a`: the same input data, no expression.
    cw.put_metric_alarm(
        AlarmName=part_alarm, Namespace=namespace, MetricName="PartA", Statistic="Maximum",
        Period=_PERIOD, EvaluationPeriods=_N, DatapointsToAlarm=_N, Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold", TreatMissingData="missing", ActionsEnabled=False,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[part_alarm]))

    switch = _now_bucket(_PERIOD) + timedelta(seconds=_PERIOD)
    _wait_for_bucket(switch)
    high: set[datetime] = set()

    def publish_high():
        b = _now_bucket(_PERIOD)
        if b not in high:
            _put(cw, namespace, "PartA", b, _PART_HIGH)
            _put(cw, namespace, "PartB", b, _PART_HIGH)
            high.add(b)

    _drive_until(
        publish_high,
        lambda: (_describe(cw, expr_alarm)["StateValue"], _describe(cw, part_alarm)["StateValue"]),
        lambda s: s[0] == "ALARM" and s[1] == "OK",
        what="a + b = 60 alarming the expression while input a = 30 alone stays OK",
    )
    rd = _words_and_data(_poll_new_state(cw, expr_alarm, "ALARM")[0], relation="greater than",
                         value=2 * _PART_HIGH, buckets=high, statistic=None, evaluated=_N)
    for dp in rd["evaluatedDatapoints"]:
        assert set(dp) == {"timestamp", "value"}, f"expression evaluatedDatapoint fields {sorted(dp)!r}"
    # The control's OK decision may cover phase-1 buckets (its first window reaches back before its
    # creation), so it is graded against EVERY value this check put into input a: each cited
    # datapoint must be one of them, and below the threshold.
    put_a = {**{b: _PART_LOW for b in low}, **{b: _PART_HIGH for b in high}}
    p_ok = _poll_new_state(cw, part_alarm, "OK")[0]
    pw = _reason(p_ok["stateReason"])
    assert (pw["rel"], pw["thr"], pw["n"]) == ("not greater than", _THRESHOLD, _N), p_ok["stateReason"]
    assert p_ok["stateReasonData"]["statistic"] == "Maximum", f"{p_ok['stateReasonData']!r}"
    cited = list(pw["cited"]) + [(dp["value"], _ts(dp["timestamp"]))
                                 for dp in p_ok["stateReasonData"]["evaluatedDatapoints"]]
    assert cited, f"the single-input OK decision cites no datapoint: {p_ok!r}"
    for v, ts in cited:
        assert put_a.get(ts) == v and v < _THRESHOLD, (
            f"the single-input alarm cites {v!r} at {ts.isoformat()}; this check put "
            f"{put_a.get(ts)!r} into input a there"
        )
    assert not [d for _, d in _state_updates(cw, part_alarm)
                if d["newState"]["stateValue"] == "ALARM"], (
        f"the single-input alarm on a = {_PART_HIGH} recorded an ALARM transition"
    )


def _words_and_data(state, *, relation, value, buckets, statistic, evaluated, sample_count=None):
    """One StateUpdate newState, field by field, against the value and buckets this check caused."""
    words = _reason(state["stateReason"])
    assert words["rel"] == relation, (
        f"StateReason says {words['rel']!r}, expected {relation!r}: {state['stateReason']!r}"
    )
    assert (words["thr"], words["n"]) == (_THRESHOLD, _N), state["stateReason"]
    assert words["k"] == len(words["cited"]) and words["k"] >= 1, state["stateReason"]
    for v, ts in words["cited"]:
        assert v == value and ts in buckets, (
            f"StateReason cites {v!r} at {ts.isoformat()}, not a {value!r} this check published"
        )
    rd = state["stateReasonData"]
    assert (rd["version"], rd["period"], rd["threshold"]) == ("1.0", _PERIOD, _THRESHOLD), f"{rd!r}"
    if statistic is None:
        assert "statistic" not in rd, f"an expression alarm's record names a statistic: {rd!r}"
    else:
        assert rd["statistic"] == statistic, f"statistic {rd.get('statistic')!r}, expected {statistic!r}"
    assert rd["recentDatapoints"] == [value] * _N, (
        f"recentDatapoints {rd['recentDatapoints']!r}, expected {[value] * _N!r}"
    )
    ev = rd["evaluatedDatapoints"]
    assert len(ev) == evaluated, f"evaluatedDatapoints {ev!r}, expected {evaluated}"
    for dp in ev:
        ts = _ts(dp["timestamp"])
        assert dp["value"] == value and ts in buckets, (
            f"evaluatedDatapoint {dp!r} is not a {value!r} published in "
            f"{sorted(b.isoformat() for b in buckets)!r}"
        )
        if sample_count is not None:
            assert dp["sampleCount"] == sample_count, f"{dp!r}: expected sampleCount {sample_count}"
        assert (dp["value"], ts) in words["cited"], f"{dp!r} is not named in {state['stateReason']!r}"
    return rd


_POLL_BUDGET_S = 300.0  # a generous ceiling for a poll to FAIL at; never asserted as a latency
_REASON_RE = re.compile(
    r"^Threshold Crossed: (?P<k>\d+) out of the last (?P<n>\d+) datapoints "
    r"\[(?P<cited>[^\]]*)\] (?:was|were) (?P<rel>[a-z ]+?) the threshold \((?P<thr>-?[0-9.]+)\) "
    r"\(minimum (?P<min>\d+) datapoints? for (?P<frm>OK|ALARM) -> (?P<to>OK|ALARM) transition\)\.$"
)
_CITED_RE = re.compile(r"(-?[0-9.]+) \((\d\d/\d\d/\d\d \d\d:\d\d:\d\d)\)")


def _reason(text):
    m = _REASON_RE.match(text or "")
    assert m, f"StateReason {text!r} is not a 'Threshold Crossed: k out of the last n datapoints' reason"
    cited = [
        (float(v), datetime.strptime(ts, "%d/%m/%y %H:%M:%S").replace(tzinfo=timezone.utc))
        for v, ts in _CITED_RE.findall(m["cited"])
    ]
    return {"k": int(m["k"]), "n": int(m["n"]), "rel": m["rel"], "thr": float(m["thr"]),
            "min": int(m["min"]), "frm": m["frm"], "to": m["to"], "cited": cited}


def _ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z").astimezone(timezone.utc)


def _now_bucket(period):
    epoch = int(time.time())
    return datetime.fromtimestamp(epoch - epoch % period, tz=timezone.utc)


def _wait_for_bucket(bucket):
    """Block until the wall clock is inside `bucket` -- so a value lands in a fresh period."""
    while datetime.now(timezone.utc) < bucket:
        time.sleep(0.5)


def _put(cw, namespace, metric, bucket, value=None, *, values=None, counts=None, dimensions=None):
    datum = {"MetricName": metric, "Timestamp": bucket, "StorageResolution": 1}
    if values is not None:
        datum["Values"], datum["Counts"] = values, counts
    else:
        datum["Value"] = value
    if dimensions:
        datum["Dimensions"] = dimensions
    cw.put_metric_data(Namespace=namespace, MetricData=[datum])


def _describe(cw, name):
    for page in cw.get_paginator("describe_alarms").paginate(
        AlarmNames=[name], AlarmTypes=["MetricAlarm"]
    ):
        for a in page.get("MetricAlarms", []):
            if a["AlarmName"] == name:
                return a
    raise AssertionError(f"alarm {name!r} is not present in DescribeAlarms")


def _state_updates(cw, name):
    out = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=name, HistoryItemType="StateUpdate", ScanBy="TimestampAscending"
    ):
        for item in page.get("AlarmHistoryItems", []):
            assert item["HistoryItemType"] == "StateUpdate", f"{item!r}"
            out.append((item, json.loads(item["HistoryData"])))
    return out


def _poll_new_state(cw, name, state):
    """The newState of every StateUpdate INTO `state`, oldest first, once at least one exists."""
    deadline = time.monotonic() + _POLL_BUDGET_S
    while True:
        items = _state_updates(cw, name)
        hits = [d["newState"] for _, d in items if d["newState"]["stateValue"] == state]
        if hits:
            return hits
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"alarm {name!r} reads {state} but its history records no StateUpdate into it: "
                f"{[d['newState']['stateValue'] for _, d in items]!r}"
            )
        time.sleep(3.0)


def _drive_until(publish, probe, predicate, *, what):
    """Keep publishing and polling until predicate(probe()); FAIL (never skip) on exhaustion."""
    deadline = time.monotonic() + _POLL_BUDGET_S
    last = None
    while True:
        publish()
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{what} never happened while the check kept publishing; "
                                 f"last observation {last!r}")
        time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
