"""deploy-sfn-fifo-queue-integration-stack."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sfn-fifo-queue-integration-stack"
GROUP = "deploy-stack"
SERVICES = ["lambda", "stepfunctions", "sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deployed stack provisions a FIFO queue and a correctly-scoped SFN execution role;
    a live SendMessage task on the deployed state machine delivers a message that preserves
    the FIFO queue's per-message-group ordering guarantee."""
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "FifoQueue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "FifoQueue": True,
                        "ContentBasedDeduplication": True,
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
                                "PolicyName": "sqs-send",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": "sqs:SendMessage",
                                            "Resource": {"Fn::GetAtt": ["FifoQueue", "Arn"]},
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
                        "DefinitionString": {
                            "Fn::Sub": json.dumps(
                                {
                                    "Comment": "send to FIFO queue",
                                    "StartAt": "Send",
                                    "States": {
                                        "Send": {
                                            "Type": "Task",
                                            "Resource": "arn:aws:states:::sqs:sendMessage",
                                            "Parameters": {
                                                "QueueUrl": "${FifoQueue}",
                                                "MessageBody.$": "$.body",
                                                "MessageGroupId.$": "$.groupId",
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
                "QueueUrl": {"Value": {"Ref": "FifoQueue"}},
                "StateMachineArn": {"Value": {"Ref": "StateMachine"}},
            },
        }
    )
    stack = _deploy_cfn(ctx, template)
    queue_url = stack["outputs"]["QueueUrl"]
    sm_arn = stack["outputs"]["StateMachineArn"]

    sfn = ctx.client("stepfunctions")
    sqs = ctx.client("sqs")
    group_id = ctx.unique_name("grp")
    bodies = [f"msg-{i}-{ctx.unique_name('m')}" for i in range(3)]
    for body in bodies:
        exec_arn = sfn.start_execution(
            stateMachineArn=sm_arn, input=json.dumps({"body": body, "groupId": group_id})
        )["executionArn"]
        status = _poll_until(
            lambda a=exec_arn: sfn.describe_execution(executionArn=a)["status"],
            lambda s: s in {"SUCCEEDED", "FAILED", "TIMED_OUT", "ABORTED"},
            timeout_s=60,
            interval_s=1.5,
            description="execution terminal",
        )
        assert status == "SUCCEEDED", f"execution {exec_arn} ended in {status}, expected SUCCEEDED"

    received: list[str] = []
    deadline = time.monotonic() + 30.0
    while len(received) < len(bodies) and time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5
        )
        for m in resp.get("Messages", []):
            received.append(m["Body"])
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])

    assert received == bodies, f"FIFO order violated: {received} != {bodies}"


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
