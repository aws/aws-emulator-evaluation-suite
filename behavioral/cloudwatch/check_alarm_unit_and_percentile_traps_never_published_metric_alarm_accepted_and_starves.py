"""alarm-unit-and-percentile-traps-never-published-metric-alarm-accepted-and-starves."""
from __future__ import annotations

# On real AWS, PutMetricAlarm on a metric name that was never
# published returns 200, and the alarm stays INSUFFICIENT_DATA with StateReason 'Unchecked: Initial
# alarm creation' while a twin on a live metric in the same namespace fires.

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "alarm-unit-and-percentile-traps-never-published-metric-alarm-accepted-and-starves"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_THRESHOLD = 10.0
_VALUE = 500.0
_HOLD_S = 120.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:negative-delivery", "cap:c2", "cap:c4", "concern:data-plane", "concern:metrics",
      "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An alarm on a metric that does not exist is accepted and waits; it is not an error.

    Two never-published-metric alarms hold INSUFFICIENT_DATA with no history while a live twin alarms."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealNeverNs")
    live_metric = "LiveMetric"
    ghost_metric = "NeverPublishedMetric"

    def _publish() -> None:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[{"MetricName": live_metric, "Timestamp": datetime.now(timezone.utc),
                         "Value": _VALUE, "Unit": "Count"}],
        )

    def _create(name, metric, tmd):
        kwargs = dict(
            AlarmName=name, Namespace=namespace, MetricName=metric, Statistic="Maximum",
            Period=60, EvaluationPeriods=1, DatapointsToAlarm=1, Threshold=_THRESHOLD,
            ComparisonOperator="GreaterThanThreshold", ActionsEnabled=False,
            AlarmDescription=f"sim2real never-published {metric} tmd={tmd!r}",
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
        if tmd is not None:
            kwargs["TreatMissingData"] = tmd
        return cw.put_metric_alarm(**kwargs)

    _publish()
    live = ctx.unique_name("sim2real-never-live-")
    resp = _create(live, live_metric, "missing")
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[live]))
    ghost_missing = ctx.unique_name("sim2real-never-ghost-missing-")
    resp_gm = _create(ghost_missing, ghost_metric, "missing")
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[ghost_missing]))
    ghost_default = ctx.unique_name("sim2real-never-ghost-default-")
    resp_gd = _create(ghost_default, ghost_metric, None)
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[ghost_default]))

    # --- beat 1: accepted, and associated with the metric that does not exist ------------------ #
    for label, r in (("live", resp), ("ghost-missing", resp_gm), ("ghost-default", resp_gd)):
        code = r["ResponseMetadata"]["HTTPStatusCode"]
        assert code == 200, f"PutMetricAlarm for {label!r} returned HTTP {code!r}, expected 200"
    ghosts = {"missing": ghost_missing, "default": ghost_default}
    baselines = {}
    for key, name in ghosts.items():
        a = _describe(cw, name)
        assert a["StateValue"] == "INSUFFICIENT_DATA", (
            f"the never-published alarm {key!r} started in {a['StateValue']!r}"
        )
        baselines[key] = a.get("StateReason")
    # On AWS, an alarm created without TreatMissingData reads back with the key
    # ABSENT (the default 'missing' behaviour is applied, not materialised into the config).
    default_alarm = _describe(cw, ghost_default)
    assert "TreatMissingData" not in default_alarm, (
        f"the alarm created without TreatMissingData read back "
        f"TreatMissingData={default_alarm.get('TreatMissingData')!r}; real AWS leaves the key absent"
    )
    associated = {
        a["AlarmName"]
        for a in cw.describe_alarms_for_metric(
            Namespace=namespace, MetricName=ghost_metric
        )["MetricAlarms"]
    }
    assert associated == {ghost_missing, ghost_default}, (
        f"DescribeAlarmsForMetric for the never-published metric returned {sorted(associated)!r}; "
        f"expected exactly the two alarms created on it -- the alarm/metric association exists "
        f"before the metric does"
    )

    # --- beat 2: the live twin fires ----------------------------------------------------------- #
    fired = _poll_until(
        lambda: _describe(cw, live),
        lambda a: a["StateValue"] == "ALARM",
        timeout_s=420.0, interval_s=15.0, on_iteration=_publish,
        description=f"the live-metric twin {live!r} reached ALARM on {_VALUE}",
    )
    window = json.loads(fired["StateReasonData"]).get("recentDatapoints")
    assert window == [_VALUE], f"the live twin fired over {window!r}, expected [{_VALUE!r}]"

    # --- beat 3: the never-published alarms stay put ------------------------------------------- #
    readings = {k: [] for k in ghosts}
    t_end = time.monotonic() + _HOLD_S
    while True:
        _publish()
        for k, n in ghosts.items():
            readings[k].append(_describe(cw, n))
        if time.monotonic() >= t_end:
            break
        time.sleep(20.0)
    for k, n in ghosts.items():
        states = [r["StateValue"] for r in readings[k]]
        assert set(states) == {"INSUFFICIENT_DATA"}, (
            f"the never-published alarm {k!r} moved during the hold: {states!r}; a metric with no "
            f"series gives the evaluator nothing to act on under TreatMissingData={k!r}"
        )
        reasons = {r.get("StateReason") for r in readings[k]}
        assert reasons == {baselines[k]}, (
            f"the never-published alarm {k!r} StateReason moved from {baselines[k]!r} to "
            f"{sorted(reasons)!r}"
        )
        updates = _state_updates(cw, n)
        assert updates == [], (
            f"the never-published alarm {k!r} has StateUpdate history {updates!r}; it has never "
            f"had a state change to record"
        )

    # --- beat 4: the metric is absent on the query path, the live one is present --------------- #
    end = datetime.now(timezone.utc) + timedelta(minutes=1)
    start = end - timedelta(minutes=20)

    def _q(qid, metric):
        return {"Id": qid, "MetricStat": {
            "Metric": {"Namespace": namespace, "MetricName": metric}, "Period": 60,
            "Stat": "Maximum"}}

    res = {r["Id"]: r for r in cw.get_metric_data(
        MetricDataQueries=[_q("ghost", ghost_metric), _q("live", live_metric)],
        StartTime=start, EndTime=end,
    )["MetricDataResults"]}
    assert res["ghost"]["StatusCode"] == "Complete" and res["ghost"]["Values"] == [], (
        f"GetMetricData for the never-published metric returned {res['ghost']!r}; expected "
        f"Complete with no values"
    )
    assert res["live"]["Values"] and set(res["live"]["Values"]) == {_VALUE}, (
        f"GetMetricData for the live metric returned {res['live']!r}; expected {_VALUE}"
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
