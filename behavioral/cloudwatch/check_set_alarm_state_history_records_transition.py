"""set-alarm-state-history-records-transition."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "set-alarm-state-history-records-transition"
GROUP = "state-machine"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """SetAlarmState forces a StateValue transition that is durably recorded in DescribeAlarmHistory
    with the exact custom StateReason text, even though the forced state may revert quickly."""
    cw = ctx.client("cloudwatch")
    alarm_name = ctx.unique_name("sim2real-behav-sashist-")
    namespace = ctx.unique_name("Sim2RealBehav/")

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="NeverPublished",
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))
    alarm_arn = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["AlarmArn"]
    cw.tag_resource(ResourceARN=alarm_arn, Tags=[{"Key": "sim2real", "Value": "true"}])

    marker = ctx.unique_name("force-alarm-reason-")
    cw.set_alarm_state(AlarmName=alarm_name, StateValue="ALARM", StateReason=marker)

    def probe():
        return cw.describe_alarm_history(
            AlarmName=alarm_name, HistoryItemType="StateUpdate", ScanBy="TimestampDescending"
        )["AlarmHistoryItems"]

    def has_marker(items):
        for item in items:
            try:
                data = json.loads(item.get("HistoryData", "{}"))
            except (ValueError, TypeError):
                continue
            if data.get("newState", {}).get("stateReason") == marker:
                return True
        return False

    items = _poll_until(probe, has_marker, timeout_s=60.0, interval_s=3.0)
    assert has_marker(items), f"StateReason marker {marker!r} not found in alarm history: {items}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
