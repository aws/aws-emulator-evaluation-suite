"""deploy-missing-lambda-invoke-permission-sfn-template-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-missing-lambda-invoke-permission-sfn-template-negative"
GROUP = "deploy-stack"
SERVICES = ["lambda", "stepfunctions", "sqs"]


@tags("axis:rejection", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A state machine whose role lacks lambda:InvokeFunction fails its Lambda Task with
    AccessDenied and never invokes the function; adding the permission to the same role makes the
    execution succeed."""
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "LambdaExecRole": {
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
                "EchoFn": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Handler": "index.handler",
                        "Runtime": "python3.12",
                        "Timeout": 5,
                        "Role": {"Fn::GetAtt": ["LambdaExecRole", "Arn"]},
                        "Code": {
                            "ZipFile": "def handler(event, context):\n    return {'echoed': event}\n"
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
                        # Deliberately NO lambda:InvokeFunction permission attached.
                    },
                },
                "StateMachine": {
                    "Type": "AWS::StepFunctions::StateMachine",
                    "Properties": {
                        "RoleArn": {"Fn::GetAtt": ["SfnRole", "Arn"]},
                        "DefinitionString": {
                            "Fn::Sub": json.dumps(
                                {
                                    "Comment": "invoke lambda",
                                    "StartAt": "Invoke",
                                    "States": {
                                        "Invoke": {
                                            "Type": "Task",
                                            "Resource": "arn:aws:states:::lambda:invoke",
                                            "Parameters": {
                                                "FunctionName": "${EchoFn}",
                                                "Payload.$": "$",
                                            },
                                            "End": True,
                                        }
                                    },
                                }
                            )
                        },
                    },
                },
            },
            "Outputs": {
                "StateMachineArn": {"Value": {"Ref": "StateMachine"}},
                "RoleName": {"Value": {"Ref": "SfnRole"}},
                "FunctionArn": {"Value": {"Fn::GetAtt": ["EchoFn", "Arn"]}},
                "FunctionName": {"Value": {"Ref": "EchoFn"}},
            },
        }
    )
    stack = _deploy_cfn(ctx, template)
    sm_arn = stack["outputs"]["StateMachineArn"]
    role_name = stack["outputs"]["RoleName"]
    fn_arn = stack["outputs"]["FunctionArn"]
    fn_name = stack["outputs"]["FunctionName"]

    sfn = ctx.client("stepfunctions")
    logs = ctx.client("logs")
    log_group_name = f"/aws/lambda/{fn_name}"

    marker_denied = ctx.unique_name("denied-marker")
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, input=json.dumps({"marker": marker_denied})
    )["executionArn"]
    status = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn)["status"],
        lambda s: s in {"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"},
        timeout_s=60,
        interval_s=1.5,
        description="execution terminal (denied)",
    )
    assert status == "FAILED", f"expected the denied execution to be FAILED, got {status!r}"
    denied_exec = sfn.describe_execution(executionArn=exec_arn)
    assert "AccessDenied" in denied_exec.get("cause", "") or "AccessDenied" in denied_exec.get(
        "error", ""
    ), f"expected an AccessDenied failure, got error={denied_exec.get('error')!r} cause={denied_exec.get('cause')!r}"
    # The cause carries a session name Step Functions chooses and a per-call Lambda request id,
    # so its stable parts are asserted.
    cause = str(denied_exec.get("cause", ""))
    assert cause.startswith("User: arn:aws:sts::"), f"expected an authorization failure, got: {cause}"
    assert f":assumed-role/{role_name}/" in cause, f"expected the state machine role, got: {cause}"
    assert "is not authorized to perform: lambda:InvokeFunction" in cause, (
        f"expected an authorization failure, got: {cause}"
    )
    assert "Status Code: 403" in cause, f"expected a 403 authorization failure, got: {cause}"

    # Effect absent, on an independent side-channel: EchoFn was never actually invoked, so Lambda
    # never created its log group for it (a log group is created lazily on first invocation, and
    # this is the function's first execution attempt ever). The IAM denial happens at the
    # Step-Functions-to-Lambda integration, before Lambda's own service ever runs the function.
    log_group_exists = _log_group_exists(logs, log_group_name)
    assert not log_group_exists, (
        f"expected no log group {log_group_name!r} (EchoFn never invoked while denied), "
        "but one already exists"
    )

    # Positive control: grant the missing permission on the SAME role, then retry.
    iam = ctx.client("iam")
    policy_name = ctx.unique_name("lambda-invoke-policy")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": fn_arn}
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )

    marker_allowed = ctx.unique_name("allowed-marker")

    def _try_execute():
        exec_arn2 = sfn.start_execution(
            stateMachineArn=sm_arn, input=json.dumps({"marker": marker_allowed})
        )["executionArn"]
        term_status = _poll_until(
            lambda: sfn.describe_execution(executionArn=exec_arn2)["status"],
            lambda s: s in {"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"},
            timeout_s=30,
            interval_s=1.5,
            description="execution terminal (allowed, retry)",
        )
        return term_status, exec_arn2

    # IAM policy attachment is eventually consistent; retry the whole execution a few times.
    final_status, final_exec_arn = _poll_until(
        _try_execute,
        lambda pair: pair[0] == "SUCCEEDED",
        timeout_s=60,
        interval_s=5.0,
        description="execution succeeds after granting permission",
    )
    assert final_status == "SUCCEEDED", (
        f"expected the execution to succeed after granting lambda:InvokeFunction, "
        f"got {final_status!r}"
    )
    output = json.loads(sfn.describe_execution(executionArn=final_exec_arn)["output"])
    assert output["Payload"]["echoed"]["marker"] == marker_allowed, (
        f"expected the invoked EchoFn to echo marker {marker_allowed!r}, "
        f"got {output['Payload']!r}"
    )

    # Mirror confirmation on the same independent side-channel: now that the call actually
    # reached Lambda, its log group exists. _poll_until raises if it never appears.
    _poll_until(
        lambda: _log_group_exists(logs, log_group_name),
        lambda exists: exists,
        timeout_s=30,
        interval_s=3.0,
        description=f"log group {log_group_name} created after a real invocation",
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _log_group_exists(logs_client: Any, log_group_name: str) -> bool:
    """True iff the CloudWatch Logs log group exists (Lambda creates it lazily on first invoke)."""
    try:
        logs_client.describe_log_streams(logGroupName=log_group_name)
        return True
    except logs_client.exceptions.ResourceNotFoundException:
        return False


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
