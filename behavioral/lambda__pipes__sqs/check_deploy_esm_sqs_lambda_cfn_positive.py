"""deploy-esm-sqs-lambda-cfn-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-esm-sqs-lambda-cfn-positive"
GROUP = "deployment-order"
SERVICES = ["lambda", "pipes", "sqs"]

_LAMBDA_CODE = (
    "import json, os, boto3\n"
    "sqs = boto3.client('sqs')\n"
    "def handler(event, context):\n"
    "    queue_url = os.environ['RESULT_QUEUE_URL']\n"
    "    for rec in event.get('Records', []):\n"
    "        sqs.send_message(QueueUrl=queue_url, MessageBody=rec.get('body', ''))\n"
    "    return {'processed': len(event.get('Records', []))}\n"
)

_LAMBDA_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}


def _build_template() -> str:
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SourceQueue": {"Type": "AWS::SQS::Queue"},
            "ResultQueue": {"Type": "AWS::SQS::Queue"},
            "LambdaExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": _LAMBDA_TRUST,
                    "Policies": [
                        {
                            "PolicyName": "AllowPollSourceSendResultAndLogs",
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
                                        "Action": "sqs:SendMessage",
                                        "Resource": {"Fn::GetAtt": ["ResultQueue", "Arn"]},
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
            "ForwarderFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaExecRole", "Arn"]},
                    "Timeout": 30,
                    "Environment": {"Variables": {"RESULT_QUEUE_URL": {"Ref": "ResultQueue"}}},
                    "Code": {"ZipFile": _LAMBDA_CODE},
                },
            },
            "Mapping": {
                "Type": "AWS::Lambda::EventSourceMapping",
                "Properties": {
                    "EventSourceArn": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                    "FunctionName": {"Ref": "ForwarderFunction"},
                    "BatchSize": 1,
                    "Enabled": True,
                },
            },
        },
        "Outputs": {
            "SourceQueueUrl": {"Value": {"Ref": "SourceQueue"}},
            "ResultQueueUrl": {"Value": {"Ref": "ResultQueue"}},
        },
    }
    return json.dumps(template)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An SQS-to-Lambda AWS::Lambda::EventSourceMapping deployed by CloudFormation delivers a sent
    message to the handler, which forwards its marker."""
    outputs = _deploy_cfn(ctx, _build_template(), timeout_s=420.0)
    source_url = outputs["outputs"]["SourceQueueUrl"]
    result_url = outputs["outputs"]["ResultQueueUrl"]

    sqs = ctx.client("sqs")
    marker = ctx.unique_name("esm-e2e-")
    sqs.send_message(QueueUrl=source_url, MessageBody=json.dumps({"marker": marker}))

    found = _poll_until(
        lambda: _drain_for_marker(sqs, result_url, marker),
        lambda body: body is not None,
        timeout_s=120.0,
        interval_s=5.0,
        description=f"delivery of marker {marker} to result queue via ESM",
    )
    assert found["marker"] == marker, f"expected forwarded marker {marker!r}, got {found['marker']!r}"


def _drain_for_marker(sqs, queue_url: str, marker: str) -> dict[str, Any] | None:
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
    for msg in resp.get("Messages", []):
        sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        try:
            body = json.loads(msg["Body"])
        except (json.JSONDecodeError, ValueError):
            continue
        if body.get("marker") == marker:
            return body
    return None


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
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError") or (
                exc.response["Error"]["Code"] == "ValidationError"
                and "does not exist" not in exc.response["Error"]["Message"]
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
