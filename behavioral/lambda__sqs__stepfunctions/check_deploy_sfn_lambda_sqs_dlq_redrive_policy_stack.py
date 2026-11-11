"""deploy-sfn-lambda-sqs-dlq-redrive-policy-stack."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sfn-lambda-sqs-dlq-redrive-policy-stack"
GROUP = "deploy-stack"
SERVICES = ["lambda", "stepfunctions", "sqs"]


# timing:real-time — visibility: 5 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A message a state machine sends to a queue whose Lambda ESM consumer always fails moves to the
    redrive-policy DLQ after maxReceiveCount receives and disappears from the source queue."""
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "DLQ": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {"MessageRetentionPeriod": 3600},
                },
                "SourceQueue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "VisibilityTimeout": 5,
                        "RedrivePolicy": {
                            "deadLetterTargetArn": {"Fn::GetAtt": ["DLQ", "Arn"]},
                            "maxReceiveCount": 2,
                        },
                    },
                },
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
                                "PolicyName": "sqs-consume",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": [
                                                "sqs:ReceiveMessage",
                                                "sqs:DeleteMessage",
                                                "sqs:GetQueueAttributes",
                                            ],
                                            "Resource": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
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
                            }
                        ],
                    },
                },
                "FailingFn": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "Handler": "index.handler",
                        "Runtime": "python3.12",
                        "Timeout": 5,
                        "Role": {"Fn::GetAtt": ["LambdaExecRole", "Arn"]},
                        "Code": {
                            "ZipFile": "def handler(event, context):\n    raise Exception('always-fails')\n"
                        },
                    },
                },
                "Esm": {
                    "Type": "AWS::Lambda::EventSourceMapping",
                    "Properties": {
                        "EventSourceArn": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                        "FunctionName": {"Ref": "FailingFn"},
                        "BatchSize": 1,
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
                                            "Resource": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
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
                                    "Comment": "send to source queue",
                                    "StartAt": "Send",
                                    "States": {
                                        "Send": {
                                            "Type": "Task",
                                            "Resource": "arn:aws:states:::sqs:sendMessage",
                                            "Parameters": {
                                                "QueueUrl": "${SourceQueue}",
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
                "SourceQueueUrl": {"Value": {"Ref": "SourceQueue"}},
                "DlqUrl": {"Value": {"Ref": "DLQ"}},
                "StateMachineArn": {"Value": {"Ref": "StateMachine"}},
                "FailingFnArn": {"Value": {"Fn::GetAtt": ["FailingFn", "Arn"]}},
            },
        }
    )
    stack = _deploy_cfn(ctx, template)
    source_url = stack["outputs"]["SourceQueueUrl"]
    dlq_url = stack["outputs"]["DlqUrl"]
    sm_arn = stack["outputs"]["StateMachineArn"]

    # Wait for the ESM to become active before feeding it work, and confirm it targets
    # the deployed function (not merely that *some* mapping reached "Enabled").
    fn_arn = stack["outputs"]["FailingFnArn"]
    lam = ctx.client("lambda")
    esm_mapping = _poll_until(
        lambda: lam.list_event_source_mappings(EventSourceArn=_queue_arn(ctx, source_url))[
            "EventSourceMappings"
        ][0],
        lambda m: m["State"] == "Enabled",
        timeout_s=90,
        interval_s=3.0,
        description="ESM Enabled",
    )
    assert esm_mapping["FunctionArn"] == fn_arn, (
        f"expected ESM wired to {fn_arn}, got {esm_mapping['FunctionArn']}"
    )

    body = f"payload-{ctx.unique_name('dlq-test')}"
    sfn = ctx.client("stepfunctions")
    sfn.start_execution(stateMachineArn=sm_arn, input=json.dumps({"body": body}))

    sqs = ctx.client("sqs")

    def _dlq_probe():
        resp = sqs.receive_message(
            QueueUrl=dlq_url, MaxNumberOfMessages=1, WaitTimeSeconds=5
        )
        return resp.get("Messages", [])

    dlq_messages = _poll_until(
        _dlq_probe,
        lambda msgs: len(msgs) > 0,
        timeout_s=90,
        interval_s=3.0,
        description="message redriven to DLQ",
    )
    assert dlq_messages[0]["Body"] == body, (
        f"expected redriven DLQ message body {body!r}, got {dlq_messages[0]['Body']!r}"
    )

    # The source queue must no longer hold the (redriven) message.
    remaining = sqs.receive_message(
        QueueUrl=source_url, MaxNumberOfMessages=1, WaitTimeSeconds=2
    ).get("Messages", [])
    assert remaining == [], f"expected source queue empty after redrive, got {remaining!r}"


def _queue_arn(ctx, queue_url: str) -> str:
    sqs = ctx.client("sqs")
    return sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])[
        "Attributes"
    ]["QueueArn"]


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
