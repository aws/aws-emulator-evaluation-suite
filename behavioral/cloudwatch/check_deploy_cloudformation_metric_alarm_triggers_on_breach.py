"""deploy-cloudformation-metric-alarm-triggers-on-breach."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cloudformation-metric-alarm-triggers-on-breach"
GROUP = "deploy"
SERVICES = ["cloudwatch"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:deploy", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A CFN-deployed metric alarm actually transitions to ALARM once breaching
    data lands -- CREATE_COMPLETE on the stack is not the finish line."""
    cfn = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")
    stack_name = ctx.unique_name("sim2real-cwalarm-stack-")
    alarm_name = ctx.unique_name("sim2real-cwalarm-")
    namespace = ctx.unique_name("Sim2RealBehav")
    metric_name = "BreachMetric"

    template = {
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
                    "Threshold": 1,
                    "ComparisonOperator": "GreaterThanThreshold",
                    "TreatMissingData": "notBreaching",
                },
            }
        }
    }
    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 1800})

    # Confirm the stack really did create a metric alarm, not just report success.
    alarms = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    assert len(alarms) == 1, "CFN-created alarm not visible via DescribeAlarms"
    # Positive control: the freshly-created alarm must not already be in ALARM before we
    # ever publish a breaching datapoint, or a target that just reports ALARM unconditionally
    # would pass this check without the breach having caused anything.
    assert alarms[0]["StateValue"] != "ALARM", (
        f"alarm was already in ALARM before any data was published: {alarms[0]['StateValue']}"
    )

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Value": 100.0, "Unit": "Count"}],
    )

    state = _poll_alarm_state(ctx, alarm_name, {"ALARM"}, timeout_s=600.0)
    assert state == "ALARM", f"expected alarm to breach into ALARM, last observed state was {state}"

    # The teardown is not the finish line either: prove the underlying CloudWatch alarm is
    # actually gone once the stack reports DELETE_COMPLETE, not just that CFN said so.
    _delete_stack(ctx, stack_name)
    remaining = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    assert remaining == [], f"alarm still visible via DescribeAlarms after stack deletion: {remaining}"


# ===== helpers =====

def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})


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
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
