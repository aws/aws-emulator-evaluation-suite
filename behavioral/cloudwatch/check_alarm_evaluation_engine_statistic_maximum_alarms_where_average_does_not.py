"""alarm-evaluation-engine-statistic-maximum-alarms-where-average-does-not."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-evaluation-engine-statistic-maximum-alarms-where-average-does-not"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_PERIOD = 10
_N = 2
_THRESHOLD = 50.0
_VALUES = [10.0, 100.0]
_COUNTS = [3.0, 1.0]           # per period: 10,10,10,100 -> Maximum 100.0, Average 32.5
_MAX = 100.0
_AVG = 32.5
_SAMPLES = 4.0


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Periods of samples 10,10,10,100 alarm a Statistic=Maximum alarm (100 > 50) and leave an
    Average alarm OK (32.5); history and GetMetricStatistics cite the same aggregated values.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealEvalEngineStat")
    metric = "Latency"
    a_max = ctx.unique_name("sim2real-eval-engine-max-")
    a_avg = ctx.unique_name("sim2real-eval-engine-avg-")
    for name, stat in ((a_max, "Maximum"), (a_avg, "Average")):
        cw.put_metric_alarm(
            AlarmName=name, Namespace=namespace, MetricName=metric, Statistic=stat,
            Period=_PERIOD, EvaluationPeriods=_N, DatapointsToAlarm=_N, Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanThreshold", TreatMissingData="missing",
            ActionsEnabled=False,
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))

    buckets: set[datetime] = set()

    def publish():
        now = _now_bucket(_PERIOD)
        for i in range(_N + 1):
            b = now - timedelta(seconds=_PERIOD * i)
            if b not in buckets:          # exactly one datum per period keeps SampleCount exact
                _put(cw, namespace, metric, b, values=_VALUES, counts=_COUNTS)
                buckets.add(b)

    _drive_until(
        publish, lambda: (_describe(cw, a_max)["StateValue"], _describe(cw, a_avg)["StateValue"]),
        lambda s: s[0] != "INSUFFICIENT_DATA" and s[1] != "INSUFFICIENT_DATA",
        what="both statistic alarms evaluating the published periods",
    )
    s_max, s_avg = _describe(cw, a_max), _describe(cw, a_avg)
    assert s_max["StateValue"] == "ALARM", (
        f"Maximum alarm over periods whose max is {_MAX} is {s_max['StateValue']!r}: "
        f"{s_max['StateReason']!r}"
    )
    assert s_avg["StateValue"] == "OK", (
        f"Average alarm over periods whose mean is {_AVG} is {s_avg['StateValue']!r}: "
        f"{s_avg['StateReason']!r}"
    )

    hit = _words_and_data(_poll_new_state(cw, a_max, "ALARM")[0], relation="greater than",
                          value=_MAX, buckets=buckets, statistic="Maximum", evaluated=_N,
                          sample_count=_SAMPLES)
    miss = _words_and_data(_poll_new_state(cw, a_avg, "OK")[0], relation="not greater than",
                           value=_AVG, buckets=buckets, statistic="Average", evaluated=1,
                           sample_count=_SAMPLES)
    assert not [d for _, d in _state_updates(cw, a_avg) if d["newState"]["stateValue"] == "ALARM"], (
        f"the Average alarm recorded an ALARM transition although every period averages {_AVG}"
    )

    # The evaluator and the query path agree on the same bucket.
    for rd in (hit, miss):
        b = _ts(rd["evaluatedDatapoints"][0]["timestamp"])
        dps = cw.get_metric_statistics(
            Namespace=namespace, MetricName=metric, StartTime=b,
            EndTime=b + timedelta(seconds=_PERIOD), Period=_PERIOD,
            Statistics=["Maximum", "Average", "SampleCount"],
        )["Datapoints"]
        assert len(dps) == 1, f"GetMetricStatistics for {b.isoformat()} returned {dps!r}"
        got = (dps[0]["Maximum"], dps[0]["Average"], dps[0]["SampleCount"])
        assert got == (_MAX, _AVG, _SAMPLES), (
            f"GetMetricStatistics for the evaluated bucket {b.isoformat()} reports "
            f"(Maximum, Average, SampleCount) {got!r}, expected {(_MAX, _AVG, _SAMPLES)!r}"
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
