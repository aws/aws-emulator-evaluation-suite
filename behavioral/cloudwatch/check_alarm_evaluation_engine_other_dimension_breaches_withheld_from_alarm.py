"""alarm-evaluation-engine-other-dimension-breaches-withheld-from-alarm."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-evaluation-engine-other-dimension-breaches-withheld-from-alarm"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_PERIOD = 10
_N = 2
_THRESHOLD = 50.0
_QUIET = 5.0
_LOUD = 99.0


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics",
      "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Breaching data under a sibling dimension value, or no dimension, never reaches the alarm's series.

    The alarm stays OK citing only its own series' 5.0, then alarms once 99.0 lands in that series."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealEvalEngineDim")
    metric = "Requests"
    mine = [{"Name": "Tenant", "Value": ctx.unique_name("mine-")}]
    other = [{"Name": "Tenant", "Value": ctx.unique_name("other-")}]
    alarm = ctx.unique_name("sim2real-eval-engine-dim-")
    cw.put_metric_alarm(
        AlarmName=alarm, Namespace=namespace, MetricName=metric, Dimensions=mine,
        Statistic="Maximum", Period=_PERIOD, EvaluationPeriods=_N, DatapointsToAlarm=_N,
        Threshold=_THRESHOLD, ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="missing", ActionsEnabled=False,
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm]))

    quiet: set[datetime] = set()

    def publish_mixed():
        now = _now_bucket(_PERIOD)
        for i in range(_N + 1):
            b = now - timedelta(seconds=_PERIOD * i)
            if b in quiet:
                continue
            _put(cw, namespace, metric, b, _LOUD, dimensions=other)
            _put(cw, namespace, metric, b, _LOUD)
            _put(cw, namespace, metric, b, _QUIET, dimensions=mine)
            quiet.add(b)

    state = _drive_until(publish_mixed, lambda: _describe(cw, alarm),
                         lambda a: a["StateValue"] != "INSUFFICIENT_DATA",
                         what="the dimensioned alarm evaluating its own series")
    assert state["StateValue"] == "OK", (
        f"the alarm on {mine!r} went {state['StateValue']!r} although its own series only ever "
        f"held {_QUIET}; {_LOUD} was published only to {other!r} and to the undimensioned metric: "
        f"{state['StateReason']!r}"
    )
    ok = _words_and_data(_poll_new_state(cw, alarm, "OK")[0], relation="not greater than",
                         value=_QUIET, buckets=quiet, statistic="Maximum", evaluated=1,
                         sample_count=1.0)
    assert not [d for _, d in _state_updates(cw, alarm) if d["newState"]["stateValue"] == "ALARM"], (
        "the alarm recorded an ALARM transition while only a sibling series breached"
    )
    b = _ts(ok["evaluatedDatapoints"][0]["timestamp"])
    for dims, want in ((other, _LOUD), ([], _LOUD), (mine, _QUIET)):
        dps = cw.get_metric_statistics(
            Namespace=namespace, MetricName=metric, Dimensions=dims, StartTime=b,
            EndTime=b + timedelta(seconds=_PERIOD), Period=_PERIOD, Statistics=["Maximum"],
        )["Datapoints"]
        assert [d["Maximum"] for d in dps] == [want], (
            f"series {dims!r} holds {dps!r} for the evaluated bucket {b.isoformat()}, expected "
            f"Maximum {want}"
        )

    # Positive control: the breach arrives on the alarm's own series in fresh periods.
    switch = _now_bucket(_PERIOD) + timedelta(seconds=_PERIOD)
    _wait_for_bucket(switch)
    loud: set[datetime] = set()

    def publish_mine_loud():
        b = _now_bucket(_PERIOD)
        if b not in loud:
            _put(cw, namespace, metric, b, _LOUD, dimensions=mine)
            loud.add(b)

    _drive_until(publish_mine_loud, lambda: _describe(cw, alarm)["StateValue"],
                 lambda s: s == "ALARM", what=f"the alarm alarming once {mine!r} itself breached")
    _words_and_data(_poll_new_state(cw, alarm, "ALARM")[0], relation="greater than", value=_LOUD,
                    buckets=loud, statistic="Maximum", evaluated=_N, sample_count=1.0)


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

# ===== helpers =====
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
