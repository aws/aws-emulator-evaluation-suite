"""cfn-deploy-alarm-invalid-metric-rejected."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-alarm-invalid-metric-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudwatch", "lambda", "logs"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A stack with two AWS/Lambda alarms deploys both; after invokes, the alarm on Invocations
    reaches ALARM while the one on a metric name that does not exist stays INSUFFICIENT_DATA:
    CloudWatch does not validate metric names at creation."""
    fn_name = _xname(ctx, "fn")
    valid_alarm = _xname(ctx, "validalarm")
    invalid_alarm = _xname(ctx, "invalidalarm")

    code = "def handler(event, context):\n    return {'ok': True}\n"

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "lambda.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                },
            },
            "AppFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": fn_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Code": {"ZipFile": code},
                    "Timeout": 30,
                },
            },
            "ValidAlarm": {
                "Type": "AWS::CloudWatch::Alarm",
                "Properties": {
                    "AlarmName": valid_alarm,
                    "Namespace": "AWS/Lambda",
                    "MetricName": "Invocations",
                    "Dimensions": [
                        {"Name": "FunctionName", "Value": {"Ref": "AppFunction"}}
                    ],
                    "Statistic": "Sum",
                    "Period": 60,
                    "EvaluationPeriods": 1,
                    "Threshold": 0,
                    "ComparisonOperator": "GreaterThanThreshold",
                },
            },
            "InvalidMetricAlarm": {
                "Type": "AWS::CloudWatch::Alarm",
                "Properties": {
                    "AlarmName": invalid_alarm,
                    "Namespace": "AWS/Lambda",
                    "MetricName": "SimTotallyBogusMetricXYZ123",
                    "Dimensions": [
                        {"Name": "FunctionName", "Value": {"Ref": "AppFunction"}}
                    ],
                    "Statistic": "Sum",
                    "Period": 60,
                    "EvaluationPeriods": 1,
                    "Threshold": 0,
                    "ComparisonOperator": "GreaterThanThreshold",
                },
            },
        },
        "Outputs": {
            "FunctionName": {"Value": {"Ref": "AppFunction"}},
            "ValidAlarmName": {"Value": {"Ref": "ValidAlarm"}},
            "InvalidAlarmName": {"Value": {"Ref": "InvalidMetricAlarm"}},
        },
    }

    _deploy_cfn(ctx, json.dumps(template))

    cw = ctx.client("cloudwatch")
    lam = ctx.client("lambda")

    # Both alarms should start life without any datapoints yet.
    initial = cw.describe_alarms(AlarmNames=[valid_alarm, invalid_alarm])["MetricAlarms"]
    by_name = {a["AlarmName"]: a for a in initial}
    assert by_name[invalid_alarm]["StateValue"] == "INSUFFICIENT_DATA", (
        f"expected fresh alarm {invalid_alarm} to start INSUFFICIENT_DATA, "
        f"got {by_name[invalid_alarm]['StateValue']!r}"
    )

    for _ in range(5):
        resp = lam.invoke(FunctionName=fn_name, InvocationType="RequestResponse", Payload=b"{}")
        assert resp["StatusCode"] == 200 and "FunctionError" not in resp, (
            f"expected a clean invoke of {fn_name}, got status={resp['StatusCode']!r} "
            f"function_error={resp.get('FunctionError')!r}"
        )

    def _valid_state():
        return cw.describe_alarms(AlarmNames=[valid_alarm])["MetricAlarms"][0]["StateValue"]

    # Positive control: the alarm on a REAL metric leaves INSUFFICIENT_DATA once invocations land.
    valid_state = _poll_until(
        _valid_state,
        lambda s: s == "ALARM",
        timeout_s=300,
        interval_s=10.0,
        description=f"alarm {valid_alarm} on real metric to reach ALARM",
    )
    assert valid_state == "ALARM", (
        f"expected {valid_alarm} on the real Invocations metric to reach ALARM, got {valid_state!r}"
    )

    # Negative: the alarm on the bogus metric name never receives a datapoint, so it must still
    # be stuck in INSUFFICIENT_DATA at this point (same elapsed window that flipped the valid one).
    invalid_state = cw.describe_alarms(AlarmNames=[invalid_alarm])["MetricAlarms"][0]["StateValue"]
    assert invalid_state == "INSUFFICIENT_DATA", (
        f"expected {invalid_alarm} on the nonexistent metric to remain INSUFFICIENT_DATA "
        f"(no datapoint can ever exist for that metric name), got {invalid_state!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] != "StackNotFoundException" and not (
                err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
