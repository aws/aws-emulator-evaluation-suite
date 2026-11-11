"""high-resolution-metric-math-alarm-not-breaching-recovers-to-ok-while-a-missing-twin-goes-insufficient-data."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "high-resolution-metric-math-alarm-not-breaching-recovers-to-ok-while-a-missing-twin-goes-insufficient-data"
GROUP = "metrics-and-alarms"
SERVICES = ["cloudwatch"]

#: A ceiling for each evaluator transition of a 10 s alarm; never asserted as a latency.
_ALARM_DEADLINE_S = 240
_PERIOD_S = 10
_BREACH = 500.0
_THRESHOLD = 100.0


# timing:real-time — metric: 10 s
@tags("axis:happy-path", "cap:c4", "concern:metrics", "plane:data", "concern:data-plane", "dp:api",
      "timing:real-time")
def run(ctx) -> None:
    """A notBreaching METRIC MATH alarm over a 10 s high-resolution series that fired on real data
    returns to OK once the series goes silent, while an identical missing twin drops to
    INSUFFICIENT_DATA: TreatMissingData is honoured for the computed series.

    Reference: https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html#alarms-and-missing-data
    """
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("sim2real-flint-") + "/Flint"
    dims = [{"Name": "Camera_name", "Value": "ALL"}, {"Name": "Operation", "Value": "FrameQuartzLag"}]
    metrics = [
        {"Id": "m1", "ReturnData": False, "MetricStat": {
            "Metric": {"Namespace": namespace, "MetricName": "Errors", "Dimensions": dims},
            "Period": _PERIOD_S, "Stat": "Maximum"}},
        {"Id": "e1", "Expression": "m1 * 2", "Label": "weighted errors", "ReturnData": True},
    ]
    names = {"notBreaching": ctx.unique_name("sim2real-silence-nb-"),
             "missing": ctx.unique_name("sim2real-silence-missing-")}
    for policy, name in names.items():
        cw.put_metric_alarm(
            AlarmName=name, Metrics=metrics,
            EvaluationPeriods=1, DatapointsToAlarm=1,
            Threshold=_THRESHOLD, ComparisonOperator="GreaterThanThreshold",
            TreatMissingData=policy, ActionsEnabled=False,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
        ctx.on_cleanup(_teardown(lambda n=name: cw.delete_alarms(AlarmNames=[n]), "ResourceNotFound"))

    stored = {p: _alarm(cw, n) for p, n in names.items()}
    for policy, alarm in stored.items():
        assert [m["Id"] for m in alarm["Metrics"]] == ["m1", "e1"], (
            f"the {policy} alarm's Metrics must still be the m1/e1 expression pair, got "
            f"{alarm.get('Metrics')!r}"
        )
        periods = [m["MetricStat"]["Period"] for m in alarm["Metrics"] if "MetricStat" in m]
        assert periods == [_PERIOD_S], (
            f"the {policy} alarm's m1 must keep its {_PERIOD_S} s high-resolution period, got "
            f"{periods!r}"
        )

    def states():
        return {p: _alarm(cw, n)["StateValue"] for p, n in names.items()}

    def publish_and_read():
        cw.put_metric_data(Namespace=namespace, MetricData=[{
            "MetricName": "Errors", "Dimensions": dims, "Value": _BREACH, "StorageResolution": 1,
            "Timestamp": datetime.now(timezone.utc)}])
        return states()

    fired = _poll(ctx, publish_and_read, lambda s: set(s.values()) == {"ALARM"},
                  timeout_s=_ALARM_DEADLINE_S, interval_s=3,
                  description="both alarms reaching ALARM on the published breach")
    assert fired == {"notBreaching": "ALARM", "missing": "ALARM"}, f"alarm states {fired!r}"

    # Publishing stops here: from now on every new period is missing data.
    settled = _poll(ctx, states, lambda s: "ALARM" not in s.values(), timeout_s=_ALARM_DEADLINE_S,
                    interval_s=3, description="both alarms leaving ALARM once the series is silent")
    assert settled == {"notBreaching": "OK", "missing": "INSUFFICIENT_DATA"}, (
        f"after the series went silent notBreaching should recover to OK and missing drop to "
        f"INSUFFICIENT_DATA, got {settled!r}"
    )

    def transitions(name):
        return [h["newState"]["stateValue"] for h in _state_updates(cw, name)]

    seq = _poll(ctx, lambda: transitions(names["notBreaching"]), lambda t: t[-2:] == ["ALARM", "OK"],
                timeout_s=120, interval_s=5,
                description="the notBreaching alarm's history ending ALARM -> OK")
    assert "INSUFFICIENT_DATA" not in seq[seq.index("ALARM"):], (
        f"the notBreaching alarm should go straight from ALARM to OK, its history is {seq!r}"
    )


# ===== helpers =====
def _poll(ctx, probe, predicate, *, timeout_s=120.0, interval_s=3.0, description="condition"):
    """Poll bounded by timeout_s and the run's remaining budget; raises quoting the last read."""
    left = ctx.time_left()
    deadline = time.monotonic() + (timeout_s if left is None else min(timeout_s, left))
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s; last {last!r}")
        time.sleep(interval_s)


def _alarm(cw, name: str) -> dict:
    """The one MetricAlarm named `name`; fails when it is not described exactly once."""
    found = cw.describe_alarms(AlarmNames=[name], AlarmTypes=["MetricAlarm"])["MetricAlarms"]
    assert len(found) == 1, f"alarm {name!r} should be described exactly once, got {found!r}"
    return found[0]


def _state_updates(cw, name: str) -> list[dict]:
    """Every StateUpdate history item's parsed HistoryData, oldest first."""
    out = []
    for page in cw.get_paginator("describe_alarm_history").paginate(
            AlarmName=name, HistoryItemType="StateUpdate", ScanBy="TimestampAscending"):
        out.extend(json.loads(i["HistoryData"]) for i in page["AlarmHistoryItems"])
    return out


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` means gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
