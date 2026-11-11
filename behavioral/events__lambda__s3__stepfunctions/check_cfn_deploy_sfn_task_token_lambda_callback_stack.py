"""cfn-deploy-sfn-task-token-lambda-callback-stack."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-sfn-task-token-lambda-callback-stack"
GROUP = "deployment-order"
SERVICES = ["events", "lambda", "s3", "stepfunctions"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deployed waitForTaskToken Lambda task lets the function resume the execution via
    SendTaskSuccess, and the state machine's terminal output reflects the value the Lambda
    computed from the callback payload."""
    lambda_code = (
        "import boto3, json\n"
        "def handler(event, context):\n"
        "    token = event.get('token')\n"
        "    inp = event.get('input', {}) or {}\n"
        "    value = inp.get('value', 0)\n"
        "    doubled = value * 2\n"
        "    sfn = boto3.client('stepfunctions')\n"
        "    sfn.send_task_success(taskToken=token, output=json.dumps({'doubled': doubled}))\n"
        "    return {'ok': True}\n"
    )

    definition = {
        "StartAt": "Callback",
        "States": {
            "Callback": {
                "Type": "Task",
                "Resource": "arn:aws:states:::lambda:invoke.waitForTaskToken",
                "Parameters": {
                    "FunctionName": "__LAMBDA_ARN__",
                    "Payload": {
                        "token.$": "$$.Task.Token",
                        "input.$": "$",
                    },
                },
                "TimeoutSeconds": 60,
                "End": True,
            }
        },
    }
    def_json = json.dumps(definition)
    before, after = def_json.split("__LAMBDA_ARN__")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "LambdaRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "lambda.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "send-task-outcome",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": ["states:SendTaskSuccess", "states:SendTaskFailure"],
                                    "Resource": "*",
                                },
                                {
                                    "Effect": "Allow",
                                    "Action": [
                                        "logs:CreateLogGroup",
                                        "logs:CreateLogStream",
                                        "logs:PutLogEvents",
                                    ],
                                    "Resource": "*",
                                },
                            ],
                        },
                    }],
                },
            },
            "CallbackFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaRole", "Arn"]},
                    "Timeout": 30,
                    "Code": {"ZipFile": lambda_code},
                },
            },
            "SfnRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Principal": {"Service": "states.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }],
                    },
                    "Policies": [{
                        "PolicyName": "invoke-callback",
                        "PolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Action": "lambda:InvokeFunction",
                                "Resource": {"Fn::GetAtt": ["CallbackFunction", "Arn"]},
                            }],
                        },
                    }],
                },
            },
            "CallbackStateMachine": {
                "Type": "AWS::StepFunctions::StateMachine",
                "Properties": {
                    "RoleArn": {"Fn::GetAtt": ["SfnRole", "Arn"]},
                    "DefinitionString": {
                        "Fn::Join": ["", [before, {"Fn::GetAtt": ["CallbackFunction", "Arn"]}, after]]
                    },
                },
            },
        },
        "Outputs": {"StateMachineArn": {"Value": {"Ref": "CallbackStateMachine"}}},
    }

    result = _deploy_cfn(ctx, json.dumps(template))
    sm_arn = result["outputs"]["StateMachineArn"]

    sfn = ctx.client("stepfunctions")
    exec_name = ctx.unique_name("callback-exec-")
    start = sfn.start_execution(
        stateMachineArn=sm_arn, name=exec_name, input=json.dumps({"value": 21})
    )
    exec_arn = start["executionArn"]

    final = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn),
        lambda d: d["status"] != "RUNNING",
        timeout_s=90,
        interval_s=2.0,
        description="task-token execution reached a terminal state",
    )
    assert final["status"] == "SUCCEEDED", final.get("error")
    out = json.loads(final["output"])
    assert out == {"doubled": 42}, f"expected callback output {{'doubled': 42}}, got {out!r}"


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
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
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


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
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
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
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
