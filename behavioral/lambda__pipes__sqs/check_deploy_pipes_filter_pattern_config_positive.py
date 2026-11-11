"""deploy-pipes-filter-pattern-config-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-pipes-filter-pattern-config-positive"
GROUP = "data-format"
SERVICES = ["lambda", "pipes", "sqs"]

_LAMBDA_CODE = (
    "import json, os, boto3\n"
    "sqs = boto3.client('sqs')\n"
    "def handler(event, context):\n"
    "    queue_url = os.environ['RESULT_QUEUE_URL']\n"
    "    records = event if isinstance(event, list) else event.get('Records', [])\n"
    "    for rec in records:\n"
    "        sqs.send_message(QueueUrl=queue_url, MessageBody=rec.get('body', ''))\n"
    "    return {'processed': len(records)}\n"
)

_LAMBDA_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}

_PIPES_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "pipes.amazonaws.com"}, "Action": "sts:AssumeRole"}
    ],
}

# Pipes drops SQS messages whose body doesn't match FilterCriteria (and deletes them from the
# source queue automatically) — see "Filtering Amazon SQS messages" in the Pipes user guide.
_FILTER_PATTERN = json.dumps({"body": {"type": ["keep"]}})


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
                            "PolicyName": "AllowSendResultAndLogs",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
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
            "PipeRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": _PIPES_TRUST,
                    "Policies": [
                        {
                            "PolicyName": "PipeAccess",
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
                                        "Action": "lambda:InvokeFunction",
                                        "Resource": {"Fn::GetAtt": ["ForwarderFunction", "Arn"]},
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "Pipe": {
                "Type": "AWS::Pipes::Pipe",
                "Properties": {
                    "RoleArn": {"Fn::GetAtt": ["PipeRole", "Arn"]},
                    "Source": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                    "SourceParameters": {
                        "SqsQueueParameters": {"BatchSize": 1},
                        "FilterCriteria": {"Filters": [{"Pattern": _FILTER_PATTERN}]},
                    },
                    "Target": {"Fn::GetAtt": ["ForwarderFunction", "Arn"]},
                    "TargetParameters": {
                        "LambdaFunctionParameters": {"InvocationType": "REQUEST_RESPONSE"}
                    },
                },
            },
        },
        "Outputs": {
            "SourceQueueUrl": {"Value": {"Ref": "SourceQueue"}},
            "ResultQueueUrl": {"Value": {"Ref": "ResultQueue"}},
        },
    }
    return json.dumps(template)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A pipe's FilterCriteria declared in the CloudFormation template delivers the matching SQS message
    to the Lambda target and drops the non-matching one."""
    outputs = _deploy_cfn(ctx, _build_template(), timeout_s=420.0)
    source_url = outputs["outputs"]["SourceQueueUrl"]
    result_url = outputs["outputs"]["ResultQueueUrl"]

    sqs = ctx.client("sqs")
    marker_drop = ctx.unique_name("filter-drop-")
    marker_keep = ctx.unique_name("filter-keep-")
    sqs.send_message(
        QueueUrl=source_url, MessageBody=json.dumps({"type": "drop", "marker": marker_drop})
    )
    sqs.send_message(
        QueueUrl=source_url, MessageBody=json.dumps({"type": "keep", "marker": marker_keep})
    )

    # Collect everything the result queue produces over a generous window (pipe startup plus
    # polling latency can take up to ~1 minute) rather than stopping the instant the "keep"
    # message shows up — a late-arriving "drop" message would otherwise be missed.
    seen_markers: set[str] = set()
    deadline = time.monotonic() + 90.0
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=result_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            sqs.delete_message(QueueUrl=result_url, ReceiptHandle=msg["ReceiptHandle"])
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                continue
            seen_markers.add(body.get("marker"))

    assert marker_keep in seen_markers, "matching message was never delivered to the target"
    assert marker_drop not in seen_markers, "non-matching message leaked past FilterCriteria"


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
