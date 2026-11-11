"""deploy-lambda-reserved-concurrency-limits-sqs-throughput-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-lambda-reserved-concurrency-limits-sqs-throughput-positive"
GROUP = "deployment-order"
SERVICES = ["lambda", "s3", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deployed CFN stack with ReservedConcurrentExecutions=1 on the SQS-triggered consumer
    forces its invocations to run strictly serially (no two overlapping in wall-clock time)."""
    fn_name = ctx.unique_name("sim2real-xsvc-fn-serial-")
    template = _build_template(fn_name)
    stack = _deploy_cfn(ctx, template)
    source_url = stack["outputs"]["SourceQueueUrl"]
    results_url = stack["outputs"]["ResultsQueueUrl"]

    sqs = ctx.client("sqs")
    n_messages = 4
    for i in range(n_messages):
        sqs.send_message(QueueUrl=source_url, MessageBody=f"msg-{i}")

    intervals = _collect_results(sqs, results_url, n_messages, timeout_s=150.0)
    intervals.sort(key=lambda iv: iv["start"])
    for i in range(len(intervals) - 1):
        # ReservedConcurrentExecutions=1 permits only one concurrent invocation, so the next
        # invocation's start must not precede the previous invocation's end (small epsilon for
        # clock skew between execution environments).
        assert intervals[i]["end"] <= intervals[i + 1]["start"] + 0.5, (
            f"invocation {i} (end={intervals[i]['end']}) overlapped invocation {i + 1} "
            f"(start={intervals[i + 1]['start']}) despite ReservedConcurrentExecutions=1"
        )


def _collect_results(sqs, queue_url, expected, timeout_s):
    out = []
    deadline = time.monotonic() + timeout_s
    while len(out) < expected and time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            out.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    if len(out) < expected:
        raise AssertionError(f"expected {expected} results, got {len(out)} within {timeout_s}s")
    return out


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
    consumer_code = (
        "import json, os, time, boto3\n"
        "sqs = boto3.client('sqs')\n"
        "RESULTS_URL = os.environ['RESULTS_QUEUE_URL']\n"
        "def handler(event, context):\n"
        "    start = time.time()\n"
        "    time.sleep(2)\n"
        "    end = time.time()\n"
        "    sqs.send_message(QueueUrl=RESULTS_URL, MessageBody=json.dumps({'start': start, 'end': end}))\n"
    )
    doc = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SourceQueue": {"Type": "AWS::SQS::Queue", "Properties": {"VisibilityTimeout": 30}},
            "ResultsQueue": {"Type": "AWS::SQS::Queue"},
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
                                    {
                                        "Effect": "Allow",
                                        "Action": "sqs:SendMessage",
                                        "Resource": {"Fn::GetAtt": ["ResultsQueue", "Arn"]},
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "ConsumerFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": fn_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["LambdaRole", "Arn"]},
                    "Timeout": 30,
                    "ReservedConcurrentExecutions": 1,
                    "Environment": {"Variables": {"RESULTS_QUEUE_URL": {"Ref": "ResultsQueue"}}},
                    "Code": {"ZipFile": consumer_code},
                },
            },
            "Esm": {
                "Type": "AWS::Lambda::EventSourceMapping",
                "Properties": {
                    "EventSourceArn": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                    "FunctionName": {"Ref": "ConsumerFunction"},
                    "BatchSize": 1,
                    "Enabled": True,
                },
            },
        },
        "Outputs": {
            "SourceQueueUrl": {"Value": {"Ref": "SourceQueue"}},
            "ResultsQueueUrl": {"Value": {"Ref": "ResultsQueue"}},
            "FunctionName": {"Value": {"Ref": "ConsumerFunction"}},
        },
    }
    return json.dumps(doc)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
