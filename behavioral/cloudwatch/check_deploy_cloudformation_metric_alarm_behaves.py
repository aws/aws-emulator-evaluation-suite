"""deploy-cloudformation-metric-alarm-behaves."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "deploy-cloudformation-metric-alarm-behaves"
GROUP = "deploy"
SERVICES = ["cloudwatch"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:metrics", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::CloudWatch::Alarm actually transitions to ALARM
    when breaching metric data is published, proving the managed resource works end to
    end -- not merely that the stack reached CREATE_COMPLETE."""
    namespace = ctx.unique_name("Sim2RealBehav")
    metric_name = ctx.unique_name("sim2real-behav-metric-")
    alarm_name = ctx.unique_name("sim2real-behav-alarm-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "TestAlarm": {
                "Type": "AWS::CloudWatch::Alarm",
                "Properties": {
                    "AlarmName": alarm_name,
                    "Namespace": namespace,
                    "MetricName": metric_name,
                    "Statistic": "Sum",
                    "Period": 60,
                    "EvaluationPeriods": 1,
                    "Threshold": 1,
                    "ComparisonOperator": "GreaterThanThreshold",
                    "TreatMissingData": "notBreaching",
                    "Tags": [{"Key": "sim2real-check", "Value": CHECK}],
                },
            }
        },
    }
    stack_name = _deploy_cfn(ctx, template)

    cw = ctx.client("cloudwatch")
    alarms = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    assert len(alarms) == 1, f"CloudFormation did not create the metric alarm {alarm_name!r}"
    assert alarms[0]["Namespace"] == namespace, (
        f"expected namespace {namespace!r}, got {alarms[0]['Namespace']!r}"
    )
    assert alarms[0]["MetricName"] == metric_name, (
        f"expected metric name {metric_name!r}, got {alarms[0]['MetricName']!r}"
    )
    # Newly created alarm has not yet been evaluated against real data.
    assert alarms[0]["StateValue"] in ("INSUFFICIENT_DATA", "OK"), (
        f"expected a fresh alarm to start INSUFFICIENT_DATA or OK, got {alarms[0]['StateValue']!r}"
    )

    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Value": 100.0}],
    )

    def probe() -> str:
        return cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]

    # CloudWatch alarms evaluate once new datapoints land within the alarm's period,
    # with typically 1-2 extra minutes of evaluation latency on top of the 60s period.
    # Use a generous bound and poll for the actual state transition.
    state = _poll_until(probe, lambda s: s == "ALARM", timeout_s=600.0, interval_s=20.0)
    assert state == "ALARM", f"expected the alarm to breach into ALARM, last observed {state!r}"

    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )
    remaining = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    assert not remaining, f"alarm {alarm_name!r} still present after stack deletion: {remaining!r}"


def _deploy_cfn(ctx: Any, template: dict[str, Any]) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-behav-stack-")
    cfn.create_stack(StackName=stack_name, TemplateBody=json.dumps(template))
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})
    return stack_name


def _poll_until(
    probe: Callable[[], Any],
    predicate: Callable[[Any], bool],
    *,
    timeout_s: float = 60.0,
    interval_s: float = 2.0,
) -> Any:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
