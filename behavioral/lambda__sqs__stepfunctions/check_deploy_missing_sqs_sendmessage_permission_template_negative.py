"""deploy-missing-sqs-sendmessage-permission-template-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-missing-sqs-sendmessage-permission-template-negative"
GROUP = "deploy-stack"
SERVICES = ["lambda", "stepfunctions", "sqs"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A state machine whose role lacks sqs:SendMessage fails its SendMessage task with AccessDenied
    and leaves the queue empty; adding the permission to the same role delivers the message."""
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Queue": {"Type": "AWS::SQS::Queue"},
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
                        # Deliberately NO SQS permissions attached.
                    },
                },
                "StateMachine": {
                    "Type": "AWS::StepFunctions::StateMachine",
                    "Properties": {
                        "RoleArn": {"Fn::GetAtt": ["SfnRole", "Arn"]},
                        "DefinitionString": {
                            "Fn::Sub": json.dumps(
                                {
                                    "Comment": "send to queue",
                                    "StartAt": "Send",
                                    "States": {
                                        "Send": {
                                            "Type": "Task",
                                            "Resource": "arn:aws:states:::sqs:sendMessage",
                                            "Parameters": {
                                                "QueueUrl": "${Queue}",
                                                "MessageBody.$": "$.body",
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
                "QueueUrl": {"Value": {"Ref": "Queue"}},
                "QueueArn": {"Value": {"Fn::GetAtt": ["Queue", "Arn"]}},
                "StateMachineArn": {"Value": {"Ref": "StateMachine"}},
                "RoleName": {"Value": {"Ref": "SfnRole"}},
            },
        }
    )
    stack = _deploy_cfn(ctx, template)
    queue_url = stack["outputs"]["QueueUrl"]
    queue_arn = stack["outputs"]["QueueArn"]
    sm_arn = stack["outputs"]["StateMachineArn"]
    role_name = stack["outputs"]["RoleName"]

    sfn = ctx.client("stepfunctions")
    sqs = ctx.client("sqs")

    body_denied = f"denied-{ctx.unique_name('m')}"
    exec_arn = sfn.start_execution(
        stateMachineArn=sm_arn, input=json.dumps({"body": body_denied})
    )["executionArn"]
    status = _poll_until(
        lambda: sfn.describe_execution(executionArn=exec_arn)["status"],
        lambda s: s in {"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"},
        timeout_s=60,
        interval_s=1.5,
        description="execution terminal (denied)",
    )
    assert status == "FAILED", (
        f"execution with a role lacking sqs:SendMessage must terminate FAILED; got {status!r}"
    )
    denied_exec = sfn.describe_execution(executionArn=exec_arn)
    assert "AccessDenied" in denied_exec.get("cause", "") or "AccessDenied" in denied_exec.get(
        "error", ""
    ), f"expected an AccessDenied failure, got error={denied_exec.get('error')!r} cause={denied_exec.get('cause')!r}"

    # Effect absent: the message never made it onto the queue.
    remaining = sqs.receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2
    ).get("Messages", [])
    assert remaining == [], (
        f"denied execution must never deliver to the queue; expected no messages, got {remaining!r}"
    )

    # Positive control: grant the missing permission on the SAME role, then retry.
    iam = ctx.client("iam")
    policy_name = ctx.unique_name("sqs-send-policy")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": queue_arn}
                ],
            }
        ),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    )

    body_allowed = f"allowed-{ctx.unique_name('m')}"

    def _try_execute():
        exec_arn2 = sfn.start_execution(
            stateMachineArn=sm_arn, input=json.dumps({"body": body_allowed})
        )["executionArn"]
        return _poll_until(
            lambda: sfn.describe_execution(executionArn=exec_arn2)["status"],
            lambda s: s in {"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"},
            timeout_s=30,
            interval_s=1.5,
            description="execution terminal (allowed, retry)",
        )

    # IAM policy attachment is eventually consistent; retry the whole execution a few times.
    final_status = _poll_until(
        _try_execute,
        lambda s: s == "SUCCEEDED",
        timeout_s=60,
        interval_s=5.0,
        description="execution succeeds after granting permission",
    )
    assert final_status == "SUCCEEDED", (
        f"execution must succeed once sqs:SendMessage is granted on the same role; got {final_status!r}"
    )

    delivered = _poll_until(
        lambda: sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        ).get("Messages", []),
        lambda msgs: len(msgs) > 0,
        timeout_s=30,
        interval_s=2.0,
        description="message delivered after fix",
    )
    assert delivered[0]["Body"] == body_allowed, (
        f"expected the allowed execution's body {body_allowed!r} on the queue, got {delivered[0]['Body']!r}"
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
