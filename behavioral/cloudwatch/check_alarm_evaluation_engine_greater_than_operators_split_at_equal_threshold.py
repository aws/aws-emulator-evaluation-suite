"""alarm-evaluation-engine-greater-than-operators-split-at-equal-threshold."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-evaluation-engine-greater-than-operators-split-at-equal-threshold"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_PERIOD = 10
_N = 2
_THRESHOLD = 50.0
_EQUAL = 50.0       # exactly the threshold
_ABOVE = 50.5       # the smallest step this check uses to cross it (exact in binary)


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """At a value equal to the threshold, GreaterThanOrEqualToThreshold alarms and GreaterThanThreshold
    reaches OK, each StateUpdate citing the published datapoints; above it, the strict one alarms.
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealEvalEngineGt")
    metric = "Edge"
    gte = ctx.unique_name("sim2real-eval-engine-gte-")
    gt = ctx.unique_name("sim2real-eval-engine-gt-")
    for name, op in ((gte, "GreaterThanOrEqualToThreshold"), (gt, "GreaterThanThreshold")):
        cw.put_metric_alarm(
            AlarmName=name, Namespace=namespace, MetricName=metric, Statistic="Maximum",
            Period=_PERIOD, EvaluationPeriods=_N, DatapointsToAlarm=_N, Threshold=_THRESHOLD,
            ComparisonOperator=op, TreatMissingData="missing", ActionsEnabled=False,
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))

    equal_buckets: set[datetime] = set()

    def publish_equal():
        # One PutMetricData per pass, so an evaluator tick never sees a partial set of buckets.
        now = _now_bucket(_PERIOD)
        fresh = [now - timedelta(seconds=_PERIOD * i) for i in range(_N + 1)]
        fresh = [b for b in fresh if b not in equal_buckets]
        if fresh:
            _put_many(cw, namespace, metric, fresh, _EQUAL)
            equal_buckets.update(fresh)

    _drive_until(
        ctx, publish_equal, lambda: (_describe(cw, gte)["StateValue"], _describe(cw, gt)["StateValue"]),
        lambda s: s[0] != "INSUFFICIENT_DATA" and s[1] != "INSUFFICIENT_DATA",
        what="both alarms evaluating the equal-to-threshold data",
    )
    s_gte, s_gt = _describe(cw, gte), _describe(cw, gt)
    assert s_gte["StateValue"] == "ALARM", (
        f"GreaterThanOrEqualToThreshold on {_EQUAL} == threshold {_THRESHOLD} is "
        f"{s_gte['StateValue']!r}, expected ALARM: {s_gte['StateReason']!r}"
    )
    assert s_gt["StateValue"] == "OK", (
        f"GreaterThanThreshold on {_EQUAL} == threshold {_THRESHOLD} is {s_gt['StateValue']!r}, "
        f"expected OK: {s_gt['StateReason']!r}"
    )

    hit = _poll_new_state(ctx, cw, gte, "ALARM")[0]
    _assert_decision(hit, "greater than or equal to", _EQUAL, equal_buckets, evaluated=_N)
    miss = _poll_new_state(ctx, cw, gt, "OK")[0]
    _assert_decision(miss, "not greater than", _EQUAL, equal_buckets, evaluated=1)
    assert not [d for _, d in _state_updates(cw, gt) if d["newState"]["stateValue"] == "ALARM"], (
        "GreaterThanThreshold recorded an ALARM transition on a value equal to its threshold"
    )

    # Positive control for the strict operator: cross the threshold in fresh periods.
    switch = _now_bucket(_PERIOD) + timedelta(seconds=_PERIOD)
    _wait_for_bucket(switch)
    above_buckets: set[datetime] = set()

    def publish_above():
        b = _now_bucket(_PERIOD)
        if b not in above_buckets:
            _put(cw, namespace, metric, b, _ABOVE)
            above_buckets.add(b)

    _drive_until(ctx, publish_above, lambda: _describe(cw, gt)["StateValue"], lambda s: s == "ALARM",
                 what=f"GreaterThanThreshold alarming once {_ABOVE} > {_THRESHOLD} was published")
    _assert_decision(_poll_new_state(ctx, cw, gt, "ALARM")[0], "greater than", _ABOVE, above_buckets,
                     evaluated=_N)


def _assert_decision(state, relation, value, buckets, *, evaluated):
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
    assert (rd["version"], rd["statistic"], rd["period"], rd["threshold"]) == (
        "1.0", "Maximum", _PERIOD, _THRESHOLD), f"stateReasonData {rd!r}"
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
        assert dp["sampleCount"] == 1.0, f"one datum per bucket was published, evaluator saw {dp!r}"
        assert (dp["value"], ts) in words["cited"], f"{dp!r} is not named in {state['stateReason']!r}"


_POLL_BUDGET_S = 300.0  # a generous ceiling for a poll to FAIL at; never asserted as a latency
_REASON_RE = re.compile(
    r"^Threshold Crossed: (?P<k>\d+) out of the last (?P<n>\d+) datapoints "
    r"\[(?P<cited>[^\]]*)\] (?:was|were) (?P<rel>[a-z ]+?) the threshold \((?P<thr>-?[0-9.]+)\) "
    r"\(minimum (?P<min>\d+) datapoints? for (?P<frm>OK|ALARM) -> (?P<to>OK|ALARM) transition\)\.$"
)
_CITED_RE = re.compile(r"(-?[0-9.]+) \((\d\d/\d\d/\d\d \d\d:\d\d:\d\d)\)")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


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


def _put_many(cw, namespace, metric, buckets, value):
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric, "Timestamp": b, "Value": value, "StorageResolution": 1}
                    for b in buckets],
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
            assert item["HistoryItemType"] == "StateUpdate", f"{item!r}"
            out.append((item, json.loads(item["HistoryData"])))
    return out


def _poll_new_state(ctx, cw, name, state):
    """The newState of every StateUpdate INTO `state`, oldest first, once at least one exists."""
    deadline = time.monotonic() + _budget_s(ctx, _POLL_BUDGET_S)
    while True:
        items = _state_updates(cw, name)
        hits = [d["newState"] for _, d in items if d["newState"]["stateValue"] == state]
        if hits:
            return hits
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    f"a StateUpdate into {state} for alarm {name!r}: the run budget ended first; "
                    f"not graded"
                )
            raise AssertionError(
                f"alarm {name!r} reads {state} but its history records no StateUpdate into it: "
                f"{[d['newState']['stateValue'] for _, d in items]!r}"
            )
        time.sleep(1.0)


def _drive_until(ctx, publish, probe, predicate, *, what):
    """Keep publishing and polling until predicate(probe()); FAIL (never skip) on exhaustion."""
    deadline = time.monotonic() + _budget_s(ctx, _POLL_BUDGET_S)
    last = None
    while True:
        publish()
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"{what}: the run budget ended first; not graded")
            raise AssertionError(f"{what} never happened while the check kept publishing; "
                                 f"last observation {last!r}")
        time.sleep(1.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
