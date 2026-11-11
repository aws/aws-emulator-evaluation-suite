"""deploy-cloudformation-alarm-behaves-on-metric-breach."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudformation-alarm-behaves-on-metric-breach"
GROUP = "deploy"
SERVICES = ["cloudwatch"]

_ALARM_TEMPLATE = json.dumps(
    {
        "Parameters": {
            "AlarmName": {"Type": "String"},
            "Namespace": {"Type": "String"},
            "MetricName": {"Type": "String"},
        },
        "Resources": {
            "TestAlarm": {
                "Type": "AWS::CloudWatch::Alarm",
                "Properties": {
                    "AlarmName": {"Ref": "AlarmName"},
                    "Namespace": {"Ref": "Namespace"},
                    "MetricName": {"Ref": "MetricName"},
                    "Statistic": "Maximum",
                    "Period": 10,
                    "EvaluationPeriods": 1,
                    "Threshold": 100,
                    "ComparisonOperator": "GreaterThanThreshold",
                    "TreatMissingData": "notBreaching",
                },
            }
        },
    }
)


# timing:real-time — metric: 10 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:metrics", "concern:negative-classes", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A CFN-deployed AWS::CloudWatch::Alarm actually transitions to ALARM on a real breach,
    not merely reports CREATE_COMPLETE for the stack. Also verifies CloudFormation rejects
    a duplicate CreateStack against an in-use stack name (overly-permissive boundary)."""
    cfn = ctx.client("cloudformation")
    cw = ctx.client("cloudwatch")

    stack_name = ctx.unique_name("sim2real-cfn-alarm-")
    alarm_name = ctx.unique_name("sim2real-alarm-")
    namespace = ctx.unique_name("Sim2RealCfnAlarm-")
    metric_name = "BreachMetric"

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_ALARM_TEMPLATE,
        Parameters=[
            {"ParameterKey": "AlarmName", "ParameterValue": alarm_name},
            {"ParameterKey": "Namespace", "ParameterValue": namespace},
            {"ParameterKey": "MetricName", "ParameterValue": metric_name},
        ],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))

    # Overly-permissive check: CFN must reject creating a second stack that reuses the
    # same stack name while the first is live -- not silently accept a duplicate.
    try:
        result = cfn.create_stack(StackName=stack_name, TemplateBody=_ALARM_TEMPLATE)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    else:
        raise AssertionError(
            f"duplicate CreateStack with an in-use stack name should have failed, got {result!r}"
        )
    assert code == "AlreadyExistsException", f"expected AlreadyExistsException, got {code!r}"
    expected_message = f"Stack [{stack_name}] already exists"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    _wait_for_stack_status(ctx, stack_name, {"CREATE_COMPLETE"}, timeout_s=300)

    # Confirm the alarm actually exists and starts non-ALARM before we breach it.
    described = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
    assert len(described) == 1, "stack claims CREATE_COMPLETE but alarm resource is absent"
    assert described[0]["Namespace"] == namespace, (
        f"CFN wired the wrong Namespace onto the alarm: expected {namespace!r}, "
        f"got {described[0]['Namespace']!r}"
    )
    assert described[0]["MetricName"] == metric_name, (
        f"CFN wired the wrong MetricName onto the alarm: expected {metric_name!r}, "
        f"got {described[0]['MetricName']!r}"
    )
    assert described[0]["StateValue"] != "ALARM", (
        f"alarm was already in ALARM state before any breaching datapoint was published: "
        f"{described[0]['StateValue']!r}"
    )

    # Publish a breaching datapoint (Threshold=100, ComparisonOperator=GreaterThanThreshold).
    cw.put_metric_data(
        Namespace=namespace,
        MetricData=[{"MetricName": metric_name, "Value": 500.0, "Unit": "Count"}],
    )

    state = _poll_alarm_state(ctx, alarm_name, "ALARM", timeout_s=240)
    assert state == "ALARM", f"alarm never transitioned to ALARM, last state was {state}"


def _wait_for_stack_status(ctx, stack_name: str, ok_statuses: set[str], timeout_s: float) -> None:
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        assert stacks, f"stack {stack_name} disappeared"
        last_status = stacks[0]["StackStatus"]
        if last_status in ok_statuses:
            return
        if last_status.endswith("FAILED") or last_status == "ROLLBACK_COMPLETE":
            raise AssertionError(f"stack {stack_name} reached {last_status}")
        time.sleep(5)
    raise AssertionError(f"stack {stack_name} never reached {ok_statuses}, last was {last_status}")


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + 300
    last_status = None
    while time.monotonic() < deadline:
        try:
            stacks = cfn.describe_stacks(StackName=stack_name)["Stacks"]
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        if not stacks:
            return
        last_status = stacks[0]["StackStatus"]
        if last_status == "DELETE_COMPLETE":
            return
        if last_status == "DELETE_FAILED":
            raise AssertionError(f"teardown of stack {stack_name} failed: DELETE_FAILED")
        time.sleep(5)
    raise AssertionError(
        f"teardown of stack {stack_name} did not reach DELETE_COMPLETE within 300s, "
        f"last status was {last_status!r}"
    )


def _poll_alarm_state(ctx, alarm_name: str, target_state: str, timeout_s: float) -> str:
    cw = ctx.client("cloudwatch")
    deadline = time.monotonic() + timeout_s
    last_state = None
    while time.monotonic() < deadline:
        alarms = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"]
        if alarms:
            last_state = alarms[0]["StateValue"]
            if last_state == target_state:
                return last_state
        time.sleep(10)
    return last_state


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
