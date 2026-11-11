"""alarm-evaluation-engine-fewer-breaches-than-evaluation-periods-withhold-alarm."""
from __future__ import annotations

import json
import re
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-evaluation-engine-fewer-breaches-than-evaluation-periods-withhold-alarm"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_PERIOD = 10
_THRESHOLD = 50.0
_LOW = 10.0
_HIGH = 90.0
_OBSERVE_PERIODS = 6   # further evaluations of the pattern watched for a forbidden ALARM


def _pattern(bucket: datetime) -> float:
    """Breach, breach, in-range, repeating by absolute bucket index: ANY three consecutive
    periods hold exactly two breaches, so three consecutive breaches never occur."""
    return _LOW if (int(bucket.timestamp()) // _PERIOD) % 3 == 0 else _HIGH


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:negative-delivery", "cap:c4", "concern:data-plane", "concern:metrics", "dp:api",
      "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Two breaches in every three periods alarm a 2-of-3 alarm and NEVER a 3-of-3 alarm on the same data.

    The 3-of-3 alarm's own record cites two breaches yet stays OK, and alarms once every period breaches."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealEvalEngineMofN")
    metric = "Pattern"
    subject = ctx.unique_name("sim2real-eval-engine-3of3-")
    control = ctx.unique_name("sim2real-eval-engine-2of3-")

    for name, dta in ((subject, 3), (control, 2)):
        cw.put_metric_alarm(
            AlarmName=name, Namespace=namespace, MetricName=metric, Statistic="Maximum",
            Period=_PERIOD, EvaluationPeriods=3, DatapointsToAlarm=dta, Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanThreshold", TreatMissingData="missing",
            ActionsEnabled=False,
        )
        ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))

    published: dict[datetime, float] = {}

    def publish_pattern():
        now = _now_bucket(_PERIOD)
        for i in range(4):
            b = now - timedelta(seconds=_PERIOD * i)
            if b in published:
                continue
            _put(cw, namespace, metric, b, _pattern(b))
            published[b] = _pattern(b)

    def both():
        return _describe(cw, subject), _describe(cw, control)

    s, c = _drive_until(
        publish_pattern, both,
        lambda sc: sc[1]["StateValue"] == "ALARM" and sc[0]["StateValue"] != "INSUFFICIENT_DATA",
        what="the 2-of-3 control alarming while the 3-of-3 subject is evaluated",
    )
    assert s["StateValue"] == "OK", (
        f"the 3-of-3 alarm is {s['StateValue']!r} on a pattern that never holds three consecutive "
        f"breaches: {s['StateReason']!r}"
    )

    # Positive control, from the evaluator's own record.
    c_alarm = _poll_new_state(cw, control, "ALARM")
    crd = c_alarm[0]["stateReasonData"]
    cw_ = _reason(c_alarm[0]["stateReason"])
    assert (cw_["k"], cw_["n"], cw_["min"], cw_["rel"], cw_["thr"]) == (2, 3, 2, "greater than", _THRESHOLD), (
        f"2-of-3 ALARM reason {c_alarm[0]['stateReason']!r}"
    )
    assert sorted(crd["recentDatapoints"]) == [_LOW, _HIGH, _HIGH], (
        f"2-of-3 alarmed on window {crd['recentDatapoints']!r}, expected one {_LOW} and two {_HIGH}"
    )
    assert len(crd["evaluatedDatapoints"]) == 2, f"{crd['evaluatedDatapoints']!r}"
    for dp in crd["evaluatedDatapoints"]:
        b = _ts(dp["timestamp"])
        assert dp["value"] == _HIGH and published.get(b) == _HIGH, (
            f"2-of-3 ALARM cites {dp!r}; this check published {published.get(b)!r} in that bucket"
        )
        assert (dp["value"], b) in cw_["cited"], f"{dp!r} not named in {c_alarm[0]['stateReason']!r}"

    # The subject saw two breaches and decided OK.
    s_ok = _poll_new_state(cw, subject, "OK")
    srd = s_ok[0]["stateReasonData"]
    assert sorted(srd["recentDatapoints"]) == [_LOW, _HIGH, _HIGH], (
        f"the 3-of-3 alarm's OK decision was over {srd['recentDatapoints']!r}; expected it to have "
        f"seen two breaches ({_HIGH}) and one in-range ({_LOW}) value and still decide OK"
    )
    sw = _reason(s_ok[0]["stateReason"])
    assert (sw["rel"], sw["thr"], sw["n"]) == ("not greater than", _THRESHOLD, 3), s_ok[0]["stateReason"]
    for value, ts in sw["cited"]:
        assert value == _LOW and published.get(ts) == _LOW, (
            f"the OK reason cites {value!r} at {ts.isoformat()}; published {published.get(ts)!r}"
        )

    # Effect absent: more pattern periods, the control stays in ALARM, the subject never alarms.
    end = _now_bucket(_PERIOD) + timedelta(seconds=_PERIOD * _OBSERVE_PERIODS)
    seen = []
    while _now_bucket(_PERIOD) < end:
        publish_pattern()
        st = _describe(cw, subject)["StateValue"]
        seen.append(st)
        assert st != "ALARM", (
            f"the 3-of-3 alarm entered ALARM although no three consecutive periods breached; "
            f"states observed {seen!r}; published {_fmt(published)}"
        )
        time.sleep(2.0)
    assert not [d for _, d in _state_updates(cw, subject) if d["newState"]["stateValue"] == "ALARM"], (
        "the 3-of-3 alarm's history records an ALARM transition on the two-in-three pattern"
    )
    assert _describe(cw, control)["StateValue"] == "ALARM", (
        "the 2-of-3 control left ALARM during the observation window, so the window proves nothing"
    )

    # Restore the one broken link: every period breaches -> the subject alarms.
    # Switch in the CURRENT bucket, which the observation loop has not filled yet: leaving a
    # period empty here would let TreatMissingData=missing reach back over the gap (measured),
    # and the ALARM would then cite non-consecutive periods.
    # (If a rollover let the loop's last publish land in it, the breach written below still makes
    # that period's Maximum the breaching value.)
    switch = _now_bucket(_PERIOD)
    breach_all: set[datetime] = set()

    def publish_all_high():
        b = _now_bucket(_PERIOD)
        _put(cw, namespace, metric, b, _HIGH)
        breach_all.add(b)

    _drive_until(publish_all_high, lambda: _describe(cw, subject),
                 lambda a: a["StateValue"] == "ALARM",
                 what="the 3-of-3 alarm alarming once every period breaches")
    s_alarm = _poll_new_state(cw, subject, "ALARM")
    ev = s_alarm[0]["stateReasonData"]["evaluatedDatapoints"]
    assert len(ev) == 3 and all(dp["value"] == _HIGH for dp in ev), f"3-of-3 ALARM evaluated {ev!r}"
    stamps = sorted(_ts(dp["timestamp"]) for dp in ev)
    assert all((b - a) == timedelta(seconds=_PERIOD) for a, b in zip(stamps, stamps[1:])), stamps
    for b in stamps:
        assert b in breach_all or published.get(b) == _HIGH, (
            f"3-of-3 ALARM cites {b.isoformat()}, a bucket this check never filled with {_HIGH}"
        )
        if _pattern(b) == _LOW:
            assert b in breach_all, (
                f"3-of-3 ALARM cites in-range-slot bucket {b.isoformat()} as breaching before the "
                f"switch at {switch.isoformat()}"
            )


def _fmt(published):
    return {b.strftime("%H:%M:%S"): v for b, v in sorted(published.items())[-9:]}


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
