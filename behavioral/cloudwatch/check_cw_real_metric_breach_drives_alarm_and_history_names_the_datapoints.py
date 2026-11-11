"""cw-real-metric-breach-drives-alarm-and-history-names-the-datapoints."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "cw-real-metric-breach-drives-alarm-and-history-names-the-datapoints"
GROUP = "evaluation"
SERVICES = ["cloudwatch"]

_THRESHOLD = 10.0
_BREACH_VALUE = 99.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "concern:data-plane", "concern:metrics", "dp:api", "plane:data", "cap:c1", "timing:real-time")
def run(ctx) -> None:
    """CloudWatch's OWN evaluator flips a real alarm on real data, and its history names the data.

    The ALARM StateUpdate carries the recentDatapoints and threshold the evaluator compared."""
    cw = ctx.client("cloudwatch")
    namespace = ctx.unique_name("Sim2RealDepthBreachNs")
    metric = "BreachMetric"
    alarm_name = ctx.unique_name("sim2real-depth-breach-")

    def _publish() -> datetime:
        now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": metric,
                    "Timestamp": now - timedelta(minutes=offset),
                    "Value": _BREACH_VALUE,
                    "Unit": "Count",
                }
                for offset in (0, 1, 2)
            ],
        )
        return now

    # Seed the evaluation window BEFORE the alarm exists, so the alarm's very first evaluation
    # already has breaching data to read. This is a latency optimisation only -- the alarm is still
    # created in INSUFFICIENT_DATA and the transition is still done by the server.
    _publish()

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName=metric,
        Statistic="Maximum",
        Period=60,
        EvaluationPeriods=1,
        DatapointsToAlarm=1,
        Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="missing",
        ActionsEnabled=False,
        AlarmDescription="sim2real depth: real breach drives the evaluator",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    # The first evaluation may land before this read; the INSUFFICIENT_DATA start is proven by the
    # ALARM transition's oldState in the history below.
    initial = _describe(cw, alarm_name)
    assert initial["StateValue"] in ("INSUFFICIENT_DATA", "ALARM"), (
        f"a freshly created alarm over breaching data reported {initial['StateValue']!r}; it "
        f"starts in INSUFFICIENT_DATA and may only evaluate to ALARM"
    )

    observed: list[str] = [initial["StateValue"]]
    deadline = time.monotonic() + 210.0
    final = initial
    while True:
        final = _describe(cw, alarm_name)
        if final["StateValue"] != observed[-1]:
            observed.append(final["StateValue"])
        if final["StateValue"] == "ALARM":
            break
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"the alarm never left {final['StateValue']!r} within 210s while "
                f"{_BREACH_VALUE} was published against a threshold of {_THRESHOLD}; observed "
                f"state sequence {observed!r}, last StateReason {final.get('StateReason')!r}. The "
                f"evaluator did not run, which is a FAIL and deliberately not a skip"
            )
        # Keep the most recent period populated: TreatMissingData='missing' makes the alarm RETAIN
        # its state across an empty period, so a single seed can stall the transition.
        _publish()
        time.sleep(15.0)

    assert final["StateReason"].startswith("Threshold Crossed"), (
        f"the evaluator's StateReason is {final['StateReason']!r}; real CloudWatch prefixes a "
        f"threshold-driven transition with 'Threshold Crossed'"
    )

    history = _poll_until(
        lambda: _state_updates(cw, alarm_name),
        lambda items: any(
            json.loads(i["HistoryData"]).get("newState", {}).get("stateValue") == "ALARM"
            for i in items
        ),
        timeout_s=60.0,
        interval_s=5.0,
        description="a StateUpdate history item recording the ALARM transition was written",
    )
    alarm_items = [
        json.loads(i["HistoryData"])
        for i in history
        if json.loads(i["HistoryData"]).get("newState", {}).get("stateValue") == "ALARM"
    ]
    hist = alarm_items[0]

    new_state = hist["newState"]
    assert new_state["stateValue"] == "ALARM", f"{hist!r}"
    reason_data = new_state["stateReasonData"]
    recent = reason_data.get("recentDatapoints")
    assert recent, (
        f"the StateUpdate carries no recentDatapoints, so the history does not evidence which data "
        f"were evaluated: {reason_data!r}"
    )
    assert _BREACH_VALUE in recent, (
        f"the evaluator's recentDatapoints are {recent!r} and do not contain the published value "
        f"{_BREACH_VALUE!r} -- the state was not derived from this check's data"
    )
    assert reason_data["threshold"] == _THRESHOLD, (
        f"the evaluator recorded threshold {reason_data['threshold']!r}, expected {_THRESHOLD!r}"
    )
    assert hist["oldState"]["stateValue"] == "INSUFFICIENT_DATA", (
        f"the transition recorded in history came from {hist['oldState']['stateValue']!r}, "
        f"expected the INSUFFICIENT_DATA the alarm was created in"
    )


# ===== helpers =====
def _describe(cw, alarm_name):
    """The metric alarm, via a paginated DescribeAlarms.

    Paginated because the account may hold other alarms. DescribeAlarms defaults AlarmTypes to
    ['MetricAlarm'] only, which is harmless here.
    """
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
        AlarmName=alarm_name, HistoryItemType="StateUpdate", ScanBy="TimestampDescending"
    ):
        items.extend(page.get("AlarmHistoryItems", []))
    return items


def _poll_until(probe, predicate, *, timeout_s, interval_s, description):
    """Poll probe() until predicate(result); FAIL on exhaustion, never skip."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} did not happen within {timeout_s}s; last observation {last!r}"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
