"""cfn-deploy-lambda-cloudwatch-alarm-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-lambda-cloudwatch-alarm-positive"
GROUP = "deployment-order"
SERVICES = ["cloudwatch", "lambda", "logs"]


# timing:real-time — metric: 60 s https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/AlarmThatSendsEmail.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A CFN stack provisioning a Lambda function plus a CloudWatch Alarm on its Errors metric
    (TreatMissingData=notBreaching) deploys, and after the function is invoked successfully
    several times (zero errors) the alarm reaches OK state."""
    fn_name = _xname(ctx, "fn")
    alarm_name = _xname(ctx, "alarm")

    code = (
        "def handler(event, context):\n"
        "    return {'ok': True}\n"
    )

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
            "ErrorsAlarm": {
                "Type": "AWS::CloudWatch::Alarm",
                "Properties": {
                    "AlarmName": alarm_name,
                    "Namespace": "AWS/Lambda",
                    "MetricName": "Errors",
                    "Dimensions": [
                        {"Name": "FunctionName", "Value": {"Ref": "AppFunction"}}
                    ],
                    "Statistic": "Sum",
                    "Period": 60,
                    "EvaluationPeriods": 1,
                    "Threshold": 1,
                    "ComparisonOperator": "GreaterThanOrEqualToThreshold",
                    "TreatMissingData": "notBreaching",
                },
            },
        },
        "Outputs": {
            "FunctionName": {"Value": {"Ref": "AppFunction"}},
            "AlarmName": {"Value": {"Ref": "ErrorsAlarm"}},
        },
    }

    _deploy_cfn(ctx, json.dumps(template))

    lam = ctx.client("lambda")
    cw = ctx.client("cloudwatch")

    # TreatMissingData=notBreaching means this alarm reaches OK from missing data
    # alone, whether invoked zero or five times, so the OK-state assertion below
    # cannot by itself catch a broken Ref-to-FunctionName dimension binding. Read
    # the deployed alarm back and confirm CFN actually wired it to this function.
    alarm_cfg = cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]
    assert alarm_cfg["Namespace"] == "AWS/Lambda", (
        f"expected alarm namespace AWS/Lambda, got {alarm_cfg['Namespace']!r}"
    )
    assert alarm_cfg["MetricName"] == "Errors", (
        f"expected alarm metric Errors, got {alarm_cfg['MetricName']!r}"
    )
    dims = {d["Name"]: d["Value"] for d in alarm_cfg["Dimensions"]}
    assert dims == {"FunctionName": fn_name}, (
        f"expected the CFN Ref on AppFunction to resolve to the deployed function "
        f"name {fn_name!r} in the alarm's Dimensions, got {dims!r}"
    )

    for _ in range(5):
        resp = lam.invoke(FunctionName=fn_name, InvocationType="RequestResponse", Payload=b"{}")
        assert resp["StatusCode"] == 200
        assert "FunctionError" not in resp

    def _state():
        return cw.describe_alarms(AlarmNames=[alarm_name])["MetricAlarms"][0]["StateValue"]

    final_state = _poll_until(
        _state,
        lambda s: s == "OK",
        timeout_s=300,
        interval_s=10.0,
        description=f"alarm {alarm_name} to reach OK",
    )
    assert final_state == "OK"

    history = cw.describe_alarm_history(
        AlarmName=alarm_name, HistoryItemType="StateUpdate"
    )["AlarmHistoryItems"]
    assert len(history) >= 1, "expected at least one recorded state-transition history item"


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
