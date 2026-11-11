"""deploy-cloudformation-alarm-update-changes-threshold-behavior."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cloudformation-alarm-update-changes-threshold-behavior"
GROUP = "deploy"
SERVICES = ["cloudwatch"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:deploy", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """Updating a CFN-managed alarm's Threshold must change how *identical*
    metric data subsequently evaluates -- the same datapoint should be OK under
    the loose threshold and ALARM under the tightened one."""
    cfn = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")
    stack_name = ctx.unique_name("sim2real-cwalarmupd-stack-")
    alarm_name = ctx.unique_name("sim2real-cwalarmupd-")
    namespace = ctx.unique_name("Sim2RealBehavUpd")
    metric_name = "SteadyMetric"
    metric_value = 50.0

    def _template(threshold: float) -> str:
        return json.dumps(
            {
                "Resources": {
                    "Alarm": {
                        "Type": "AWS::CloudWatch::Alarm",
                        "Properties": {
                            "AlarmName": alarm_name,
                            "Namespace": namespace,
                            "MetricName": metric_name,
                            "Statistic": "Maximum",
                            "Period": 60,
                            "EvaluationPeriods": 1,
                            "Threshold": threshold,
                            "ComparisonOperator": "GreaterThanThreshold",
                            "TreatMissingData": "notBreaching",
                        },
                    }
                }
            }
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(1000),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Value": metric_value, "Unit": "Count"}],
    )
    state_before = _poll_alarm_state(ctx, alarm_name, {"OK", "ALARM"}, timeout_s=600.0)
    assert state_before == "OK", f"expected OK under loose threshold 1000, got {state_before}"

    cfn.update_stack(StackName=stack_name, TemplateBody=_template(10))
    cfn.get_waiter("stack_update_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Value": metric_value, "Unit": "Count"}],
    )
    # NB: the alarm's state is already "OK" from before the update, so we must
    # poll specifically for the ALARM transition -- polling for {"OK","ALARM"}
    # would match immediately on the stale pre-update state.
    state_after = _poll_alarm_state(ctx, alarm_name, {"ALARM"}, timeout_s=600.0)
    assert state_after == "ALARM", (
        f"same metric value ({metric_value}) should now breach the tightened threshold (10), "
        f"got {state_after}"
    )


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 420})


def _poll_alarm_state(ctx, alarm_name: str, target_states, timeout_s: float = 600.0, interval_s: float = 15.0):
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cw.describe_alarms(AlarmNames=[alarm_name])
        alarms = resp.get("MetricAlarms", [])
        if alarms:
            last = alarms[0]["StateValue"]
            if last in target_states:
                return last
        time.sleep(interval_s)
    raise TimeoutError(
        f"alarm {alarm_name} did not reach {sorted(target_states)} within {timeout_s}s; last observed state: {last!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
