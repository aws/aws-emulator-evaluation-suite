"""describe-alarm-history-purged-when-alarm-deleted."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "describe-alarm-history-purged-when-alarm-deleted"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After DeleteAlarms, the alarm is gone from DescribeAlarms but DescribeAlarmHistory still
    returns its pre-deletion history items: CloudWatch retains the history of deleted alarms
    for two weeks."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-alarm-")

    cw.put_metric_alarm(
        AlarmName=name,
        ComparisonOperator="GreaterThanThreshold",
        EvaluationPeriods=1,
        MetricName="CPUUtilization",
        Namespace="AWS/EC2",
        Period=60,
        Statistic="Average",
        Threshold=90.0,
        ActionsEnabled=False,
        TreatMissingData="notBreaching",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    deleted = {"done": False}

    def _cleanup():
        if not deleted["done"]:
            try:
                cw.delete_alarms(AlarmNames=[name])
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFound":
                    raise

    ctx.on_cleanup(_cleanup)

    # Force a StateUpdate history entry in addition to the Create entry.
    cw.set_alarm_state(AlarmName=name, StateValue="ALARM", StateReason="behavioral-test")

    # Wait until history has recorded at least the creation + state update.
    items = []
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        items = cw.describe_alarm_history(AlarmName=name)["AlarmHistoryItems"]
        if len(items) >= 2:
            break
        time.sleep(1.0)
    assert len(items) >= 2, f"expected alarm history to record creation+state-update, got {items}"
    baseline_count = len(items)

    cw.delete_alarms(AlarmNames=[name])
    deleted["done"] = True

    # The alarm itself is gone...
    remaining_alarms = cw.describe_alarms(AlarmNames=[name])["MetricAlarms"]
    assert remaining_alarms == [], f"deleted alarm {name} still returned by DescribeAlarms"

    # ...but its pre-deletion history is retained (CloudWatch keeps history of active AND
    # deleted alarms for two weeks) -- history is NOT purged when the alarm is deleted.
    # Poll briefly for read-after-write consistency, but expect the entries to persist.
    after_delete = []
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        after_delete = cw.describe_alarm_history(AlarmName=name)["AlarmHistoryItems"]
        if len(after_delete) >= baseline_count:
            break
        time.sleep(1.0)
    assert len(after_delete) >= baseline_count, (
        f"expected alarm history for deleted alarm {name} to remain retained "
        f"(CloudWatch keeps history of deleted alarms for two weeks), "
        f"baseline={baseline_count} after_delete={len(after_delete)}: {after_delete}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

