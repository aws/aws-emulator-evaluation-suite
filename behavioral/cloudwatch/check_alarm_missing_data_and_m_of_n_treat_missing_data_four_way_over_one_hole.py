"""alarm-missing-data-and-m-of-n-treat-missing-data-four-way-over-one-hole."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-missing-data-and-m-of-n-treat-missing-data-four-way-over-one-hole"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_THRESHOLD = 10.0
_CLEAR = 1.0
_BREACH = 99.0
_POLICIES = ("breaching", "notBreaching", "ignore", "missing")

# Verbatim StateReason strings CloudWatch writes when the hole reaches each arm.
_REASON_BREACHING = (
    "Threshold Crossed: no datapoints were received for 1 period and 1 missing datapoint was "
    "treated as [Breaching]."
)
_REASON_NOT_BREACHING = (
    "Threshold Crossed: no datapoints were received for 1 period and 1 missing datapoint was "
    "treated as [NonBreaching]."
)
_REASON_MISSING = "Insufficient Data: 1 datapoint was unknown."


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "cap:c1", "timing:real-time")
def run(ctx) -> None:
    """Over one data hole, the four TreatMissingData policies reach their documented states.

    An OK and an ALARM baseline make `ignore` distinguishable: it must retain each prior state.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
    """
    cw = ctx.client("cloudwatch")
    # Metrics cannot be deleted, so the namespace is unique per run.
    namespace = ctx.unique_name("Sim2RealTmdHole")
    metrics = {"clear": ("ClearBaseline", _CLEAR), "breach": ("BreachBaseline", _BREACH)}
    baseline_state = {"clear": "OK", "breach": "ALARM"}
    published: list[datetime] = []

    def _publish_both() -> None:
        head = _floor10(datetime.now(timezone.utc))
        stamps = [head - timedelta(seconds=10 * i) for i in range(6)]
        for metric, value in metrics.values():
            # Maximum over a repeated identical value is idempotent, so re-publishing the last
            # minute on every pass cannot change any bucket's statistic.
            cw.put_metric_data(
                Namespace=namespace,
                MetricData=[
                    {"MetricName": metric, "Timestamp": s, "Value": value, "Unit": "Count",
                     "StorageResolution": 1}
                    for s in stamps
                ],
            )
        published.append(head)

    _publish_both()

    alarms: dict[tuple[str, str], str] = {}
    for key, (metric, _value) in metrics.items():
        for policy in _POLICIES:
            name = ctx.unique_name(f"sim2real-tmd4-{key}-{policy.lower()}-")
            cw.put_metric_alarm(
                AlarmName=name,
                Namespace=namespace,
                MetricName=metric,
                Statistic="Maximum",
                Period=10,  # high resolution: the hole reaches the arms in ~100 s rather than ~450 s
                EvaluationPeriods=1,
                DatapointsToAlarm=1,
                Threshold=_THRESHOLD,
                ComparisonOperator="GreaterThanThreshold",
                TreatMissingData=policy,
                ActionsEnabled=False,
                AlarmDescription=f"sim2real: TreatMissingData={policy} over a hole after {key}",
                Tags=[{"Key": "sim2real", "Value": CHECK}],
            )
            ctx.on_cleanup(lambda n=name: cw.delete_alarms(AlarmNames=[n]))
            alarms[(key, policy)] = name

    # The eight alarms must be identical apart from TreatMissingData (and, across the two sets,
    # the metric), or no divergence below can be attributed to the policy.
    described = {k: _describe(cw, n) for k, n in alarms.items()}
    for (key, policy), a in described.items():
        assert a.get("TreatMissingData") == policy, (
            f"alarm {key}/{policy} reads back TreatMissingData {a.get('TreatMissingData')!r}"
        )
        # The data already exists, so an alarm's first evaluation may land before this read.
        assert a["StateValue"] in ("INSUFFICIENT_DATA", baseline_state[key]), (
            f"alarm {key}/{policy} started in {a['StateValue']!r}, expected INSUFFICIENT_DATA or "
            f"its evaluated baseline {baseline_state[key]!r}"
        )
    shape = {
        k: tuple(a.get(f) for f in ("Namespace", "Statistic", "Period", "EvaluationPeriods",
                                    "DatapointsToAlarm", "Threshold", "ComparisonOperator"))
        for k, a in described.items()
    }
    assert len(set(shape.values())) == 1, (
        f"the eight alarms differ in more than TreatMissingData and metric: {shape!r}"
    )

    # Real data drives every alarm to its evaluated baseline.
    deadline = time.monotonic() + _budget_s(ctx, 300.0)
    while True:
        _publish_both()
        now_alarms = {k: _describe(cw, n) for k, n in alarms.items()}
        now_states = {k: a["StateValue"] for k, a in now_alarms.items()}
        if all(now_states[(key, p)] == baseline_state[key] for key in metrics for p in _POLICIES):
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    "the eight alarms to reach their evaluated baseline: the run budget ended "
                    "first; not graded"
                )
            raise AssertionError(
                f"the eight alarms did not all reach their evaluated baseline (clear->OK, "
                f"breach->ALARM) within the wait bound of real data; states {now_states!r}"
            )
        time.sleep(2.0)

    # Stop publishing HERE. Everything after this line is the hole.
    last_publish = published[-1]
    hole_began = datetime.now(timezone.utc)
    # The reads that observed every baseline, taken before the hole could reach any arm.
    baseline = now_alarms
    for (key, policy), a in baseline.items():
        metric, value = metrics[key]
        assert a["StateValue"] == baseline_state[key], (
            f"{key}/{policy} left its baseline {baseline_state[key]!r} before the hole: {a!r}"
        )
        assert a["StateReason"].startswith("Threshold Crossed: 1 out of the last 1 datapoints ["
                                           f"{value}"), (
            f"{key}/{policy}'s baseline must be an EVALUATED verdict over the published value "
            f"{value!r}, got StateReason {a['StateReason']!r}"
        )

    # Poll until every arm that must move has moved; `ignore` is judged only after that.
    movers = {
        ("clear", "breaching"): "ALARM",
        ("breach", "notBreaching"): "OK",
        ("clear", "missing"): "INSUFFICIENT_DATA",
        ("breach", "missing"): "INSUFFICIENT_DATA",
    }
    holders = {(key, "ignore"): baseline_state[key] for key in metrics}
    deadline = time.monotonic() + _budget_s(ctx, 600.0)
    while True:
        current = {k: _describe(cw, n) for k, n in alarms.items()}
        for k, want in holders.items():
            assert current[k]["StateValue"] == want, (
                f"TreatMissingData='ignore' on the {k[0]} metric moved from its evaluated baseline "
                f"{want!r} to {current[k]['StateValue']!r} during the hole (reason "
                f"{current[k]['StateReason']!r}); 'ignore' must retain the prior state"
            )
        if all(current[k]["StateValue"] == want for k, want in movers.items()):
            break
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(
                    "every moving arm to move during the hole: the run budget ended first; not "
                    "graded"
                )
            raise AssertionError(
                f"the hole never reached every moving arm within the wait bound: "
                f"{ {k: current[k]['StateValue'] for k in movers}!r}, expected {movers!r}"
            )
        time.sleep(2.0)

    final = {k: _describe(cw, n) for k, n in alarms.items()}
    expected_final = {
        ("clear", "breaching"): "ALARM", ("clear", "notBreaching"): "OK",
        ("clear", "ignore"): "OK", ("clear", "missing"): "INSUFFICIENT_DATA",
        ("breach", "breaching"): "ALARM", ("breach", "notBreaching"): "OK",
        ("breach", "ignore"): "ALARM", ("breach", "missing"): "INSUFFICIENT_DATA",
    }
    got_final = {k: a["StateValue"] for k, a in final.items()}
    assert got_final == expected_final, (
        f"the post-hole decision table is {got_final!r}, expected {expected_final!r}"
    )
    # The four policies over the SAME hole on the clear metric reach THREE states, and the ignore
    # arm is the only one whose outcome flips with the pre-hole data.
    assert final[("clear", "ignore")]["StateValue"] != final[("breach", "ignore")]["StateValue"], (
        "'ignore' ended in the same state after an OK baseline and an ALARM baseline, so it is not "
        "retaining anything"
    )

    # The movers name the treatment they applied, verbatim.
    assert final[("clear", "breaching")]["StateReason"] == _REASON_BREACHING, (
        f"breaching arm reason {final[('clear', 'breaching')]['StateReason']!r}"
    )
    assert final[("breach", "notBreaching")]["StateReason"] == _REASON_NOT_BREACHING, (
        f"notBreaching arm reason {final[('breach', 'notBreaching')]['StateReason']!r}"
    )
    for key in metrics:
        assert final[(key, "missing")]["StateReason"] == _REASON_MISSING, (
            f"missing arm ({key}) reason {final[(key, 'missing')]['StateReason']!r}"
        )

    # Each mover's transition in HISTORY left the evaluated baseline, not INSUFFICIENT_DATA.
    for k, want in movers.items():
        items = _state_updates(cw, alarms[k])
        assert items, f"{k} has no StateUpdate history at all"
        newest = json.loads(items[0]["HistoryData"])
        assert newest["newState"]["stateValue"] == want, (
            f"{k}'s newest StateUpdate is not the move to {want!r}: {newest!r}"
        )
        assert newest["oldState"]["stateValue"] == baseline_state[k[0]], (
            f"{k}'s hole transition did not leave the evaluated baseline "
            f"{baseline_state[k[0]]!r}: {newest!r}"
        )

    # Effect absent on the ignore arms: no state update after the baseline was reached, and
    # the state timestamp has not moved.
    for k in holders:
        before, after = baseline[k], final[k]
        assert after["StateUpdatedTimestamp"] == before["StateUpdatedTimestamp"], (
            f"ignore arm {k} was re-stated during the hole: StateUpdatedTimestamp "
            f"{before['StateUpdatedTimestamp']!r} -> {after['StateUpdatedTimestamp']!r}"
        )
        items = _state_updates(cw, alarms[k])
        moves = [json.loads(i["HistoryData"]) for i in items]
        assert [(m["oldState"]["stateValue"], m["newState"]["stateValue"]) for m in moves] == [
            ("INSUFFICIENT_DATA", holders[k])
        ], (
            f"ignore arm {k} must have exactly one state update (INSUFFICIENT_DATA -> "
            f"{holders[k]}); history holds {[i['HistorySummary'] for i in items]!r}"
        )

    # The hole is real and the data before it is real: read both back from the metric itself.
    for key, (metric, value) in metrics.items():
        before_hole = _datapoints(cw, namespace, metric, last_publish - timedelta(seconds=50),
                                  last_publish + timedelta(seconds=10))
        assert before_hole and {d["Maximum"] for d in before_hole} == {value}, (
            f"the {key} metric's pre-hole datapoints read back as {before_hole!r}, expected "
            f"Maximum {value!r}"
        )
        in_hole = _datapoints(cw, namespace, metric, hole_began + timedelta(seconds=10),
                              datetime.now(timezone.utc))
        assert in_hole == [], (
            f"the {key} metric holds datapoints inside the hole {in_hole!r}; the states above would "
            f"not be about missing data"
        )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _floor10(t: datetime) -> datetime:
    return t.replace(second=t.second - t.second % 10, microsecond=0)


def _describe(cw, alarm_name):
    for page in cw.get_paginator("describe_alarms").paginate(
        AlarmNames=[alarm_name], AlarmTypes=["MetricAlarm"]
    ):
        for alarm in page.get("MetricAlarms", []):
            if alarm["AlarmName"] == alarm_name:
                return alarm
    raise AssertionError(f"alarm {alarm_name!r} is not present in DescribeAlarms")


def _state_updates(cw, alarm_name):
    """StateUpdate history, newest first, paginated."""
    items = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
        AlarmName=alarm_name, HistoryItemType="StateUpdate", ScanBy="TimestampDescending"
    ):
        items.extend(page.get("AlarmHistoryItems", []))
    return items


def _datapoints(cw, namespace, metric, start, end):
    resp = cw.get_metric_statistics(
        Namespace=namespace, MetricName=metric, StartTime=start, EndTime=end,
        Period=10, Statistics=["Maximum"],
    )
    return sorted(resp["Datapoints"], key=lambda d: d["Timestamp"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
