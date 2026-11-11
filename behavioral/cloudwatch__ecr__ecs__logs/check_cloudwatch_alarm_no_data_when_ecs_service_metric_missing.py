"""cloudwatch-alarm-no-data-when-ecs-service-metric-missing."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "cloudwatch-alarm-no-data-when-ecs-service-metric-missing"
GROUP = "evaluation"
SERVICES = ["cloudwatch", "ecr", "ecs", "logs"]

_CONTROL_BUDGET_S = 240.0
_POLL_INTERVAL_S = 5.0


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:negative-delivery", "cap:c4", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """An alarm on a non-existent ECS service dimension stays INSUFFICIENT_DATA and never fires ALARM.

    A control alarm on published breaching data must reach ALARM by real evaluation meanwhile.
    """
    cw = ctx.client("cloudwatch")

    missing_dimensions = [
        {"Name": "ClusterName", "Value": ctx.unique_name("sim2real-behav-nonexistent-cl-")},
        {"Name": "ServiceName", "Value": ctx.unique_name("sim2real-behav-nonexistent-svc-")},
    ]
    alarm_name = ctx.unique_name("sim2real-behav-nodata-alarm-")
    cw.put_metric_alarm(
        AlarmName=alarm_name,
        Namespace="AWS/ECS",
        MetricName="CPUUtilization",
        Dimensions=missing_dimensions,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="missing",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[alarm_name]))

    control_namespace = ctx.unique_name("Sim2RealNoDataCtl")
    control_metric = "BreachingControl"
    control_alarm_name = ctx.unique_name("sim2real-behav-nodata-control-")
    cw.put_metric_alarm(
        AlarmName=control_alarm_name,
        Namespace=control_namespace,
        MetricName=control_metric,
        Statistic="Average",
        Period=60,
        EvaluationPeriods=1,
        Threshold=1.0,
        ComparisonOperator="GreaterThanThreshold",
        TreatMissingData="missing",
    )
    ctx.on_cleanup(lambda: cw.delete_alarms(AlarmNames=[control_alarm_name]))

    # Both alarms are polled in the same loop so the negative and the control share instants;
    # the control is driven by real data, never SetAlarmState, so a stub evaluator cannot pass.
    # The control's evaluated ALARM is the barrier: the negative is read once more after it, so its
    # absence of ALARM spans at least one real evaluation of both alarms.
    left = ctx.time_left()
    budget_s = _CONTROL_BUDGET_S if left is None else max(1.0, min(_CONTROL_BUDGET_S, left - 5.0))
    deadline = time.monotonic() + budget_s
    seen_states: set[str] = set()
    control_reason = ""
    control_state = ""
    while control_state != "ALARM" and time.monotonic() < deadline:
        state = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]
        seen_states.add(state)
        assert state != "ALARM", "alarm fired ALARM against a dimension pair with no published data"

        cw.put_metric_data(
            Namespace=control_namespace,
            MetricData=[{"MetricName": control_metric, "Value": 5.0, "Unit": "Count"}],
        )
        control = cw.describe_alarms(AlarmNames=[control_alarm_name])["MetricAlarms"][0]
        control_state = control["StateValue"]
        control_reason = control["StateReason"]
        if control_state != "ALARM":
            time.sleep(_POLL_INTERVAL_S)
    state = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]
    seen_states.add(state)
    assert state != "ALARM", "alarm fired ALARM against a dimension pair with no published data"

    assert "INSUFFICIENT_DATA" in seen_states, f"alarm never reached INSUFFICIENT_DATA, saw {seen_states}"
    if control_state != "ALARM" and budget_s < _CONTROL_BUDGET_S:
        raise TimeoutError(
            f"the run budget ended after {budget_s:.0f}s, before the control alarm's evaluation "
            f"(last state {control_state!r}); not graded"
        )
    assert control_state == "ALARM", (
        f"positive control alarm on a metric WITH published breaching data never reached ALARM "
        f"within {_CONTROL_BUDGET_S:.0f}s (last state {control_state!r}); the evaluator must "
        f"actually be running for the negative result above to mean anything"
    )
    assert control_reason.startswith("Threshold Crossed"), (
        f"control alarm reached ALARM via StateReason {control_reason!r}; a real evaluator "
        f"decision is prefixed 'Threshold Crossed', so this was not a genuine evaluation"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
