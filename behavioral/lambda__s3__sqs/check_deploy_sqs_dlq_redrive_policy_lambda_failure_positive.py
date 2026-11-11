"""deploy-sqs-dlq-redrive-policy-lambda-failure-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sqs-dlq-redrive-policy-lambda-failure-positive"
GROUP = "deployment-order"
SERVICES = ["lambda", "s3", "sqs"]


# timing:real-time — visibility: 5 s https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html
@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A deployed CFN stack wiring a source queue's RedrivePolicy to a DLQ moves a message
    there after the ESM-triggered Lambda repeatedly fails to process it."""
    fn_name = ctx.unique_name("sim2real-xsvc-fn-alwaysfail-")
    template = _build_template(fn_name)
    stack = _deploy_cfn(ctx, template)
    source_url = stack["outputs"]["SourceQueueUrl"]
    dlq_url = stack["outputs"]["DlqUrl"]

    sqs = ctx.client("sqs")
    sqs.send_message(QueueUrl=source_url, MessageBody="dlq-test-message")

    # VisibilityTimeout=5s * maxReceiveCount=2 plus Lambda/ESM retry overhead.
    dlq_message = _poll_until(
        lambda: _receive_one(sqs, dlq_url),
        lambda m: m is not None,
        timeout_s=120,
        interval_s=3.0,
        description="message redriven to the DLQ",
    )
    assert dlq_message["Body"] == "dlq-test-message", (
        f"expected the message redriven to the DLQ to keep its original body "
        f"'dlq-test-message', got {dlq_message['Body']!r}"
    )

    # ApproximateNumberOfMessages/ApproximateNumberOfMessagesNotVisible are eventually
    # consistent, so a single read right after the DLQ receive can still show the source
    # queue as non-empty; poll for a bounded window instead of trusting one snapshot.
    deadline = time.monotonic() + 30
    drained_attrs = None
    while time.monotonic() < deadline:
        drained_attrs = sqs.get_queue_attributes(
            QueueUrl=source_url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        if (
            int(drained_attrs["ApproximateNumberOfMessages"]) == 0
            and int(drained_attrs["ApproximateNumberOfMessagesNotVisible"]) == 0
        ):
            break
        time.sleep(3)
    assert (
        int(drained_attrs["ApproximateNumberOfMessages"]) == 0
        and int(drained_attrs["ApproximateNumberOfMessagesNotVisible"]) == 0
    ), f"expected the source queue fully drained after redrive to the DLQ, got {drained_attrs}"


def _receive_one(sqs, queue_url):
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
    msgs = resp.get("Messages", [])
    if not msgs:
        return None
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
    return msgs[0]


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


def _xsvc_resource_tags() -> dict:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list:
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


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0):
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict = {
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


def _build_template(fn_name: str) -> str:
    fail_code = "def handler(event, context):\n    raise Exception('always fails')\n"
    doc = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Dlq": {"Type": "AWS::SQS::Queue"},
            "SourceQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "VisibilityTimeout": 5,
                    "RedrivePolicy": {
                        "deadLetterTargetArn": {"Fn::GetAtt": ["Dlq", "Arn"]},
                        "maxReceiveCount": 2,
                    },
                },
            },
            "LambdaRole": {
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
                            "PolicyName": "exec",
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
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "sqs:ReceiveMessage",
                                            "sqs:DeleteMessage",
                                            "sqs:GetQueueAttributes",
                                        ],
                                        "Resource": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "FailingFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": fn_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaRole", "Arn"]},
                    "Timeout": 3,
                    "Code": {"ZipFile": fail_code},
                },
            },
            "Esm": {
                "Type": "AWS::Lambda::EventSourceMapping",
                "Properties": {
                    "EventSourceArn": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                    "FunctionName": {"Ref": "FailingFunction"},
                    "BatchSize": 1,
                    "Enabled": True,
                },
            },
        },
        "Outputs": {
            "SourceQueueUrl": {"Value": {"Ref": "SourceQueue"}},
            "DlqUrl": {"Value": {"Ref": "Dlq"}},
        },
    }
    return json.dumps(doc)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
