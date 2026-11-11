"""get-metric-data-read-calls-do-not-appear-in-alarm-history."""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "get-metric-data-read-calls-do-not-appear-in-alarm-history"
GROUP = "telemetry"
SERVICES = ["cloudwatch"]


@tags("axis:happy-path", "cap:c2", "concern:metrics", "dp:api", "plane:data")
def run(ctx) -> None:
    """Pure read operations never generate alarm history entries."""
    cw = ctx.client("cloudwatch")
    name = ctx.unique_name("sim2real-behav-readonly-")

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
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[name]))

    baseline = []
    deadline = time.monotonic() + 20.0
    while time.monotonic() < deadline:
        baseline = cw.describe_alarm_history(AlarmName=name)["AlarmHistoryItems"]
        if len(baseline) >= 1:
            break
        time.sleep(1.0)
    assert len(baseline) >= 1, "expected the alarm-creation history entry to appear"
    baseline_count = len(baseline)

    end = datetime.now(timezone.utc)
    start = end - timedelta(hours=1)

    cw.get_metric_data(
        MetricDataQueries=[
            {
                "Id": "m1",
                "MetricStat": {
                    "Metric": {"Namespace": "AWS/EC2", "MetricName": "CPUUtilization"},
                    "Period": 300,
                    "Stat": "Average",
                },
            }
        ],
        StartTime=start,
        EndTime=end,
    )
    cw.get_metric_statistics(
        Namespace="AWS/EC2",
        MetricName="CPUUtilization",
        StartTime=start,
        EndTime=end,
        Period=300,
        Statistics=["Average"],
    )
    cw.get_metric_widget_image(
        MetricWidget=json.dumps({"metrics": [["AWS/EC2", "CPUUtilization"]], "period": 300})
    )

    after = cw.describe_alarm_history(AlarmName=name)["AlarmHistoryItems"]
    assert len(after) == baseline_count, (
        f"read-only calls must not add alarm history entries: "
        f"baseline={baseline_count} after={len(after)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
