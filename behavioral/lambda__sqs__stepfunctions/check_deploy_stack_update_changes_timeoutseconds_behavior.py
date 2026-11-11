"""deploy-stack-update-changes-timeoutseconds-behavior."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-stack-update-changes-timeoutseconds-behavior"
GROUP = "deploy-stack"
SERVICES = ["lambda", "stepfunctions", "sqs"]


# timing:real-time — workflow: 1 s https://docs.aws.amazon.com/step-functions/latest/dg/state-task.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A slow Lambda Task that succeeds under a generous TimeoutSeconds fails with States.Timeout
    after a stack update tightens the timeout."""
    sleep_seconds = 4

    definition_string_sub = (
        '{"Comment":"sleepy lambda with a parametrized timeout","StartAt":"Invoke",'
        '"States":{"Invoke":{"Type":"Task","Resource":"arn:aws:states:::lambda:invoke",'
        '"TimeoutSeconds":${TaskTimeoutSeconds},'
        '"Parameters":{"FunctionName":"${SleepFn}","Payload.$":"$"},"End":true}}}'
    )

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {"TaskTimeoutSeconds": {"Type": "Number"}},
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
                        "Policies": [
                            {
                                "PolicyName": "logs",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "logs:CreateLogGroup",
                                                "logs:CreateLogStream",
                                                "logs:PutLogEvents",
                                            ],
                                            "Resource": "*",
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                "SleepFn": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Handler": "index.handler",
                        "Runtime": "python3.12",
                        "Timeout": 30,
                        "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                        "Code": {
                            "ZipFile": (
                                "import time\n"
                                "def handler(event, context):\n"
                                f"    time.sleep({sleep_seconds})\n"
                                "    return {'ok': True}\n"
                            )
                        },
                    },
                },
                "SfnRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "states.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "Policies": [
                            {
                                "PolicyName": "invoke",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "lambda:InvokeFunction",
                                            "Resource": {"Fn::GetAtt": ["SleepFn", "Arn"]},
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                "StateMachine": {
                    "Type": "AWS::StepFunctions::StateMachine",
                    "Properties": {
                        "RoleArn": {"Fn::GetAtt": ["SfnRole", "Arn"]},
                        "DefinitionString": {"Fn::Sub": definition_string_sub},
                    },
                },
            },
            "Outputs": {"StateMachineArn": {"Value": {"Ref": "StateMachine"}}},
        }
    )

    # Create with a generous timeout (30s) >> sleep (4s). The template stays FIXED across
    # create and update; only the TaskTimeoutSeconds PARAMETER value changes on update.
    stack = _deploy_cfn(ctx, template, parameters={"TaskTimeoutSeconds": "30"})
    sm_arn = stack["outputs"]["StateMachineArn"]
    stack_name = stack["stack_name"]

    sfn = ctx.client("stepfunctions")

    exec1 = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps({}))["executionArn"]
    status1 = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec1)["status"],
        lambda s: s in {"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"},
        timeout_s=30,
        interval_s=1.0,
        description="execution terminal (generous timeout)",
    )
    assert status1 == "SUCCEEDED", f"expected SUCCEEDED under the 30s timeout, got {status1}"

    # Update the stack: same template, tighten TaskTimeoutSeconds to 1s (<< the 4s sleep).
    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=template,
        Parameters=[{"ParameterKey": "TaskTimeoutSeconds", "ParameterValue": "1"}],
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_FAILED"},
        timeout_s=180,
        interval_s=5.0,
        description="stack update terminal",
    )
    updated_status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
    assert updated_status == "UPDATE_COMPLETE", (
        f"expected UPDATE_COMPLETE after tightening TaskTimeoutSeconds, got {updated_status}"
    )

    # Phase 2: same 4s sleep, now against a 1s timeout -> States.Timeout.
    exec2 = sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps({}))["executionArn"]
    status2 = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec2)["status"],
        lambda s: s in {"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"},
        timeout_s=30,
        interval_s=1.0,
        description="execution terminal (tight timeout)",
    )
    assert status2 == "FAILED", (
        f"expected FAILED once TaskTimeoutSeconds (1s) < sleep ({sleep_seconds}s), got {status2}"
    )
    failed_exec = sfn.describe_execution(executionArn=exec2)
    assert failed_exec["error"] == "States.Timeout", (
        f"expected States.Timeout, got {failed_exec.get('error')!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
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


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
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
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
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
