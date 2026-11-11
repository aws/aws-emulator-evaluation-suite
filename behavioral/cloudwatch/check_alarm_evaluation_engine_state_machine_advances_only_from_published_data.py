"""alarm-evaluation-engine-state-machine-advances-only-from-published-data."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-evaluation-engine-state-machine-advances-only-from-published-data"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_PERIOD = 10          # high-resolution alarm: the evaluator runs per 10 s bucket
_EVAL_PERIODS = 3
_THRESHOLD = 50.0
_LOW = 12.0           # in range for GreaterThanThreshold 50
_HIGH = 87.0          # breaching


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Published datapoints alone (never SetAlarmState) drive the alarm INSUFFICIENT_DATA -> OK ->
    ALARM -> OK, and each StateUpdate in the history cites exactly the datapoints this check
    published: EvaluationPeriods consecutive breaches for ALARM, one in-range point for OK."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealEvalEngineSm")
    metric = "Load"
    alarm = ctx.unique_name("sim2real-eval-engine-sm-")

    cw.put_metric_alarm(
        AlarmName=alarm,
        Namespace=namespace,
        MetricName=metric,
        Statistic="Maximum",
        Period=_PERIOD,
        EvaluationPeriods=_EVAL_PERIODS,
        DatapointsToAlarm=_EVAL_PERIODS,
        Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="missing",
        ActionsEnabled=False,
        AlarmDescription="sim2real alarm-evaluation-engine state machine",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm]))

    # --- 1. no data yet: INSUFFICIENT_DATA, and nothing evaluated -----------------------------
    # AWS records the initial StateReason as 'Unchecked: Initial alarm creation'.
    initial = _describe(cw, alarm)
    assert initial["StateValue"] == "INSUFFICIENT_DATA", (
        f"a new alarm on a metric with no data reported {initial['StateValue']!r}; it must be "
        f"INSUFFICIENT_DATA"
    )
    assert initial["StateReason"] == "Unchecked: Initial alarm creation", (
        f"initial StateReason was {initial['StateReason']!r}"
    )
    assert _state_updates(cw, alarm) == [], (
        "a StateUpdate history item exists before any datapoint was published"
    )

    low_buckets: set[datetime] = set()
    high_buckets: set[datetime] = set()
    resume_buckets: set[datetime] = set()

    # --- 2. in-range data covering EvaluationPeriods -> OK ---------------------------------------
    def publish_low():
        now = _now_bucket(_PERIOD)
        for i in range(_EVAL_PERIODS + 1):
            b = now - timedelta(seconds=_PERIOD * i)
            _put(cw, namespace, metric, b, _LOW)
            low_buckets.add(b)

    _drive_until(publish_low, lambda: _describe(cw, alarm),
                 lambda a: a["StateValue"] != "INSUFFICIENT_DATA",
                 what="the alarm leaving INSUFFICIENT_DATA on in-range data")
    after_low = _describe(cw, alarm)
    assert after_low["StateValue"] == "OK", (
        f"in-range data ({_LOW} vs threshold {_THRESHOLD}) moved the alarm to "
        f"{after_low['StateValue']!r}, not OK: {after_low['StateReason']!r}"
    )

    # --- 3. breaching data, one fresh bucket at a time -> ALARM ----------------------------------
    # Only the CURRENT bucket gets the breaching value, so the window fills with breaches one
    # period at a time and the evaluator must see 1, then 2, breaching periods before a third.
    first_high = _now_bucket(_PERIOD) + timedelta(seconds=_PERIOD)
    _wait_for_bucket(first_high)

    def publish_high():
        b = _now_bucket(_PERIOD)
        _put(cw, namespace, metric, b, _HIGH)
        high_buckets.add(b)

    _drive_until(publish_high, lambda: _describe(cw, alarm),
                 lambda a: a["StateValue"] == "ALARM",
                 what=f"the alarm reaching ALARM on {_EVAL_PERIODS} consecutive breaching periods")

    # --- 4. in-range data resumes in fresh buckets -> OK ------------------------------------------
    resume = max(high_buckets) + timedelta(seconds=_PERIOD)
    _wait_for_bucket(resume)

    def publish_resume():
        b = _now_bucket(_PERIOD)
        if b in high_buckets:
            return
        _put(cw, namespace, metric, b, _LOW)
        resume_buckets.add(b)

    back_ok = _drive_until(publish_resume, lambda: _describe(cw, alarm),
                           lambda a: a["StateValue"] == "OK",
                           what="the alarm returning to OK once in-range data resumed")

    # --- 5. the evaluator's own record of all three transitions ----------------------------------
    # Each StateUpdate's oldState is the previous one's newState; evaluatedDatapoints holds only the
    # datapoints justifying the transition, in the StateReason's bracketed order. CloudWatch has no
    # DeleteMetric, so the per-run namespace simply expires with its data. Publishing stops here, so
    # later evaluations of the emptied window may append transitions; the first three are this run's.
    items = _poll_history(cw, alarm, 3)[:3]
    pairs = [(d["oldState"]["stateValue"], d["newState"]["stateValue"]) for _, d in items]
    assert pairs == [("INSUFFICIENT_DATA", "OK"), ("OK", "ALARM"), ("ALARM", "OK")], (
        f"StateUpdate history recorded transitions {pairs!r}"
    )
    for idx, (item, data) in enumerate(items):
        old, new = data["oldState"]["stateValue"], data["newState"]["stateValue"]
        assert item["HistoryItemType"] == "StateUpdate", f"{item!r}"
        assert item["AlarmName"] == alarm, f"history item names {item['AlarmName']!r}"
        assert item["HistorySummary"] == f"Alarm updated from {old} to {new}", (
            f"HistorySummary was {item['HistorySummary']!r}"
        )
        assert data["version"] == "1.0", f"HistoryData version {data.get('version')!r}"
        if idx:
            assert data["oldState"] == items[idx - 1][1]["newState"], (
                f"transition {idx}'s oldState {data['oldState']!r} is not the previous "
                f"transition's newState {items[idx - 1][1]['newState']!r}"
            )

    ok1, alarm_t, ok2 = (d["newState"] for _, d in items)

    # INSUFFICIENT_DATA -> OK: cites only the in-range value, from buckets this check filled.
    _assert_common(ok1, _EVAL_PERIODS)
    w1 = _reason(ok1["stateReason"])
    assert w1["rel"] == "not greater than", f"OK reason relation {w1['rel']!r}: {ok1['stateReason']!r}"
    assert (w1["frm"], w1["to"]) == ("ALARM", "OK"), f"{ok1['stateReason']!r}"
    assert w1["k"] == len(w1["cited"]) and w1["k"] >= 1, f"{ok1['stateReason']!r}"
    for value, ts in w1["cited"]:
        assert value == _LOW and ts in low_buckets, (
            f"the OK reason cites {value!r} at {ts.isoformat()}, which this check did not publish "
            f"as an in-range datapoint (in-range buckets {sorted(b.isoformat() for b in low_buckets)!r})"
        )
    rd1 = ok1["stateReasonData"]
    assert rd1["recentDatapoints"] == [_LOW] * _EVAL_PERIODS, (
        f"OK recentDatapoints {rd1['recentDatapoints']!r}, expected {[_LOW] * _EVAL_PERIODS!r}"
    )
    _assert_evaluated_in_words(rd1, w1)
    for dp in rd1["evaluatedDatapoints"]:
        assert dp["value"] == _LOW and _ts(dp["timestamp"]) in low_buckets, f"{dp!r}"

    # OK -> ALARM: exactly EvaluationPeriods breaching datapoints, consecutive, all this check's.
    _assert_common(alarm_t, _EVAL_PERIODS)
    w2 = _reason(alarm_t["stateReason"])
    assert w2["rel"] == "greater than", f"ALARM reason relation {w2['rel']!r}"
    assert (w2["k"], w2["min"], w2["frm"], w2["to"]) == (_EVAL_PERIODS, _EVAL_PERIODS, "OK", "ALARM"), (
        f"the ALARM reason does not say {_EVAL_PERIODS} of {_EVAL_PERIODS} datapoints crossed: "
        f"{alarm_t['stateReason']!r}"
    )
    rd2 = alarm_t["stateReasonData"]
    assert rd2["recentDatapoints"] == [_HIGH] * _EVAL_PERIODS, (
        f"ALARM recentDatapoints {rd2['recentDatapoints']!r}: the window that alarmed contained a "
        f"non-breaching value, i.e. the evaluator alarmed on fewer than {_EVAL_PERIODS} breaches"
    )
    ev = rd2["evaluatedDatapoints"]
    assert len(ev) == _EVAL_PERIODS, f"ALARM evaluatedDatapoints {ev!r}"
    stamps = sorted(_ts(dp["timestamp"]) for dp in ev)
    for dp in ev:
        assert dp["value"] == _HIGH, f"ALARM evaluated a non-breaching datapoint {dp!r}"
        assert _ts(dp["timestamp"]) in high_buckets, (
            f"ALARM cites bucket {dp['timestamp']!r}, which this check never filled with "
            f"{_HIGH}; breaching buckets were {sorted(b.isoformat() for b in high_buckets)!r}"
        )
    assert all((b - a) == timedelta(seconds=_PERIOD) for a, b in zip(stamps, stamps[1:])), (
        f"the {_EVAL_PERIODS} breaching datapoints are not consecutive periods: {stamps!r}"
    )
    assert stamps[0] >= first_high, (
        f"ALARM window starts at {stamps[0].isoformat()}, before the first breach {first_high.isoformat()}"
    )
    assert _ts(rd2["startDate"]) == stamps[0], (
        f"ALARM startDate {rd2['startDate']!r} is not the oldest evaluated bucket {stamps[0].isoformat()}"
    )
    assert _ts(rd2["queryDate"]) >= stamps[-1] + timedelta(seconds=_PERIOD), (
        f"queryDate {rd2['queryDate']!r} precedes the end of the newest evaluated bucket"
    )
    _assert_evaluated_in_words(rd2, w2)

    # ALARM -> OK: the in-range datapoint that ended the breach, from a resumed bucket.
    _assert_common(ok2, _EVAL_PERIODS)
    w3 = _reason(ok2["stateReason"])
    assert w3["rel"] == "not greater than", f"{ok2['stateReason']!r}"
    assert (w3["min"], w3["frm"], w3["to"]) == (1, "ALARM", "OK"), f"{ok2['stateReason']!r}"
    rd3 = ok2["stateReasonData"]
    assert _LOW in rd3["recentDatapoints"] and set(rd3["recentDatapoints"]) <= {_LOW, _HIGH}, (
        f"ALARM -> OK recentDatapoints {rd3['recentDatapoints']!r}"
    )
    assert rd3["evaluatedDatapoints"], f"ALARM -> OK cites no evaluated datapoint: {rd3!r}"
    for dp in rd3["evaluatedDatapoints"]:
        assert dp["value"] == _LOW and _ts(dp["timestamp"]) in resume_buckets, (
            f"ALARM -> OK cites {dp!r}, not a resumed in-range bucket "
            f"{sorted(b.isoformat() for b in resume_buckets)!r}"
        )
    _assert_evaluated_in_words(rd3, w3)

    # The read that observed the return to OK, taken while in-range data was still being published.
    final = back_ok
    assert final["StateValue"] == "OK" and final["StateReason"] == ok2["stateReason"], (
        f"DescribeAlarms {final['StateValue']!r}/{final['StateReason']!r} disagrees with the last "
        f"StateUpdate {ok2['stateReason']!r}"
    )
    assert json.loads(final["StateReasonData"]) == rd3, (
        f"DescribeAlarms StateReasonData {final['StateReasonData']!r} != history {rd3!r}"
    )


def _assert_common(state, n):
    rd = state["stateReasonData"]
    w = _reason(state["stateReason"])
    assert w["thr"] == _THRESHOLD and w["n"] == n, f"reason {state['stateReason']!r}"
    assert rd["version"] == "1.0", f"stateReasonData version {rd.get('version')!r}"
    assert rd["statistic"] == "Maximum", f"statistic {rd.get('statistic')!r}"
    assert rd["period"] == _PERIOD, f"period {rd.get('period')!r}"
    assert rd["threshold"] == _THRESHOLD, f"threshold {rd.get('threshold')!r}"
    assert len(rd["recentDatapoints"]) == n, f"recentDatapoints {rd['recentDatapoints']!r}"


def _assert_evaluated_in_words(rd, words):
    cited = [(v, ts) for v, ts in words["cited"]]
    for dp in rd["evaluatedDatapoints"]:
        pair = (dp["value"], _ts(dp["timestamp"]))
        assert pair in cited, (
            f"evaluatedDatapoint {dp!r} is not named in the StateReason's datapoint list {cited!r}"
        )


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


def _put(cw, namespace, metric, bucket, value):
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric, "Timestamp": bucket, "Value": value,
                     "StorageResolution": 1}],
    )


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
            out.append((item, json.loads(item["HistoryData"])))
    return out


def _poll_history(cw, name, count):
    deadline = time.monotonic() + _POLL_BUDGET_S
    while True:
        items = _state_updates(cw, name)
        if len(items) >= count:
            return items
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"alarm {name!r} changed state but its history holds {len(items)} StateUpdate "
                f"items, expected {count}: {[d['newState']['stateValue'] for _, d in items]!r}"
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
            raise AssertionError(
                f"{what} never happened while the check kept publishing; last observation "
                f"{last.get('StateValue') if isinstance(last, dict) else last!r} / "
                f"{last.get('StateReason') if isinstance(last, dict) else ''!r}"
            )
        time.sleep(2.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
