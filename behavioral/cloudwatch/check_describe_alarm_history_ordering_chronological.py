"""describe-alarm-history-ordering-chronological."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "describe-alarm-history-ordering-chronological"
GROUP = "ordering"
SERVICES = ["cloudwatch"]


_REASON_PREFIX = "sim2real-behav transition "


def _state_reason(item: dict) -> str:
    return json.loads(item["HistoryData"])["newState"]["stateReason"]


def _driven(items: list) -> list:
    """The items this check's SetAlarmState calls logged. SetAlarmState: "Metric alarms returns to
    their actual state quickly, often within seconds", which logs CloudWatch's own items too."""
    return [item for item in items if _state_reason(item).startswith(_REASON_PREFIX)]


def _poll_for_history(cw, alarm_name: str, expected_count: int, timeout_s: float = 60.0):
    deadline = time.monotonic() + timeout_s
    items: list = []
    while time.monotonic() < deadline:
        resp = cw.describe_alarm_history(
            AlarmName=alarm_name, HistoryItemType="StateUpdate", ScanBy="TimestampDescending", MaxRecords=50
        )
        items = resp["AlarmHistoryItems"]
        if len(_driven(items)) >= expected_count:
            return items
        time.sleep(2)
    raise AssertionError(f"expected at least {expected_count} driven StateUpdate history items, got {len(_driven(items))}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeAlarmHistory with ScanBy=TimestampDescending lists StateUpdate items newest first,
    the driven SetAlarmState items in reverse call order; ScanBy=TimestampAscending lists the same
    driven items oldest first.
    """
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-history-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=ctx.unique_name("Sim2RealBehavHistoryNS"),
        MetricName="RequestCount",
        Statistic="Sum",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        Tags=[{"Key": "sim2real-behav", "Value": alarm_name}],
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    # The alarm has no data, so its actual state is INSUFFICIENT_DATA and CloudWatch may return it
    # there between calls; every driven state differs from that, so each call is a transition.
    transitions = ["ALARM", "OK", "ALARM", "OK", "ALARM"]
    for i, state in enumerate(transitions):
        cw.set_alarm_state(
            AlarmName=alarm_name,
            StateValue=state,
            StateReason=f"{_REASON_PREFIX}{i}: {state}",
        )
        time.sleep(1.5)  # keep transitions timestamp-distinguishable

    items_desc = _poll_for_history(cw, alarm_name, expected_count=len(transitions), timeout_s=60.0)

    timestamps_desc = [item["Timestamp"] for item in items_desc]
    assert timestamps_desc == sorted(timestamps_desc, reverse=True), "TimestampDescending order was not respected"

    # The driven items must appear in exactly the reverse order we drove them.
    driven_desc = _driven(items_desc)
    our_reasons_newest_first = [_state_reason(item) for item in driven_desc]
    expected_newest_first = [f"{_REASON_PREFIX}{i}: {state}" for i, state in enumerate(transitions)][::-1]
    assert our_reasons_newest_first == expected_newest_first, (
        f"expected newest-first order {expected_newest_first}, got {our_reasons_newest_first}"
    )

    resp_asc = cw.describe_alarm_history(
        AlarmName=alarm_name, HistoryItemType="StateUpdate", ScanBy="TimestampAscending", MaxRecords=50
    )
    items_asc = resp_asc["AlarmHistoryItems"]
    timestamps_asc = [item["Timestamp"] for item in items_asc]
    assert timestamps_asc == sorted(timestamps_asc), "TimestampAscending order was not respected"
    # CloudWatch may log its own items between the two reads, so the scans are compared on the
    # driven items only.
    driven_asc = _driven(items_asc)
    assert [_state_reason(item) for item in driven_asc] == our_reasons_newest_first[::-1], (
        "ascending and descending scans disagree on the driven items' order"
    )
    assert [item["Timestamp"] for item in driven_asc] == [item["Timestamp"] for item in driven_desc][::-1], (
        "ascending and descending scans disagree on the driven items' timestamps"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
