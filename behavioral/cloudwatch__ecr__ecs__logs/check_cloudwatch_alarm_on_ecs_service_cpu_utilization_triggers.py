"""cloudwatch-alarm-on-ecs-service-cpu-utilization-triggers."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "cloudwatch-alarm-on-ecs-service-cpu-utilization-triggers"
GROUP = "alerting"
SERVICES = ["cloudwatch", "ecr", "ecs", "logs"]


_THRESHOLD = 75.0
_BREACH_VALUE = 92.0
_CLEAR_VALUE = 8.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:metrics", "plane:control", "timing:real-time")
def run(ctx) -> None:
    """A CPUUtilization-shaped alarm is moved to ALARM and back to OK by CloudWatch's evaluator from
    published datapoints, each StateReason starting 'Threshold Crossed' and the history recording
    the ALARM transition; SetAlarmState is never used, so the evaluator itself is exercised."""
    ecs = ctx.client("ecs")
    cw = ctx.client("cloudwatch")

    cluster_name = ctx.unique_name("sim2real-behav-cl-")
    ecs.create_cluster(clusterName=cluster_name)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=cluster_name))

    namespace = ctx.unique_name("Sim2RealEcsCpuNs")
    service_name = ctx.unique_name("sim2real-behav-svc-")
    alarm_name = ctx.unique_name("sim2real-behav-alarm-")
    dimensions = [
        {"Name": "ClusterName", "Value": cluster_name},
        {"Name": "ServiceName", "Value": service_name},
    ]

    def _publish(value: float) -> None:
        cw.put_metric_data(
            Namespace=namespace,
            MetricData=[
                {
                    "MetricName": "CPUUtilization",
                    "Dimensions": dimensions,
                    "Timestamp": _minute_floor(),
                    "Value": value,
                    "Unit": "Percent",
                }
            ],
        )

    # Warm the metric before the alarm exists, so evaluation is not also waiting on CloudWatch to
    # first discover a brand-new namespace.
    _publish(_BREACH_VALUE)

    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace=namespace,
        MetricName="CPUUtilization",
        Dimensions=dimensions,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        DatapointsToAlarm=1,
        Threshold=_THRESHOLD,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="missing",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    alarm_state = _poll_until(
        lambda: _describe(cw, alarm_name),
        lambda a: a["StateValue"] == "ALARM",
        timeout_s=200.0,
        interval_s=15.0,
        description=(
            f"alarm {alarm_name!r} evaluated to ALARM from a published {_BREACH_VALUE} "
            f"CPUUtilization datapoint against a threshold of {_THRESHOLD}"
        ),
        on_iteration=lambda: _publish(_BREACH_VALUE),
    )
    assert alarm_state["StateReason"].startswith("Threshold Crossed"), (
        f"the ALARM transition's StateReason is {alarm_state['StateReason']!r}, expected a real "
        f"evaluated transition prefixed 'Threshold Crossed' -- this one was not produced by "
        f"CloudWatch's own evaluator"
    )

    history = cw.describe_alarm_history(AlarmName=alarm_name, HistoryItemType="StateUpdate")["AlarmHistoryItems"]
    new_states = [json.loads(item["HistoryData"])["newState"]["stateValue"] for item in history]
    assert "ALARM" in new_states, f"alarm history does not record the transition into ALARM, saw {new_states}"

    ok_state = _poll_until(
        lambda: _describe(cw, alarm_name),
        lambda a: a["StateValue"] == "OK",
        timeout_s=90.0,
        interval_s=15.0,
        description=(
            f"alarm {alarm_name!r} evaluated back to OK from a published {_CLEAR_VALUE} "
            f"CPUUtilization datapoint"
        ),
        on_iteration=lambda: _publish(_CLEAR_VALUE),
    )
    assert ok_state["StateReason"].startswith("Threshold Crossed"), (
        f"the OK transition's StateReason is {ok_state['StateReason']!r}, expected a real "
        f"evaluated transition prefixed 'Threshold Crossed' -- this one was not produced by "
        f"CloudWatch's own evaluator"
    )


def _minute_floor():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).replace(second=0, microsecond=0)


def _describe(cw, alarm_name: str) -> dict[str, Any]:
    alarms: list[dict[str, Any]] = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    if not alarms:
        raise AssertionError(f"alarm {alarm_name!r} is not present in DescribeAlarms")
    return alarms[0]


def _poll_until(probe, predicate, *, timeout_s, interval_s, description, on_iteration=None):
    """Poll probe() until predicate(result); FAIL on exhaustion, never skip."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} did not happen within {timeout_s}s; last observation {last!r}")
        if on_iteration is not None:
            on_iteration()
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
