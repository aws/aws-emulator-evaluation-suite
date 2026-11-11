"""cfn-deploy-sqs-esm-filter-criteria-positive."""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-sqs-esm-filter-criteria-positive"
GROUP = "deploy-esm"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed SQS-triggered event source mapping with FilterCriteria only invokes the
    Lambda for messages matching the pattern; non-matching messages are silently dropped by
    Lambda's poller (never invoke the function) and both classes disappear from the source queue."""
    role_name = _xname(ctx, "role")
    source_queue_name = _xname(ctx, "srcq")
    sentinel_queue_name = _xname(ctx, "sentinelq")
    function_name = _xname(ctx, "fn")

    filter_pattern = json.dumps({"body": {"type": ["important"]}})

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "RoleName": {"Type": "String"},
            "SourceQueueName": {"Type": "String"},
            "SentinelQueueName": {"Type": "String"},
            "FunctionName": {"Type": "String"},
        },
        "Resources": {
            "SourceQueue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": {"Ref": "SourceQueueName"}}},
            "SentinelQueue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": {"Ref": "SentinelQueueName"}}},
            "LambdaRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Ref": "RoleName"},
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
                        ],
                    },
                    "Policies": [
                        {
                            "PolicyName": "EsmAccess",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                                        "Resource": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": ["sqs:SendMessage"],
                                        "Resource": {"Fn::GetAtt": ["SentinelQueue", "Arn"]},
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                                        "Resource": "*",
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "Function": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": {"Ref": "FunctionName"},
                    "Role": {"Fn::GetAtt": ["LambdaRole", "Arn"]},
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Timeout": 15,
                    "Environment": {"Variables": {"SENTINEL_QUEUE_URL": {"Ref": "SentinelQueue"}}},
                    "Code": {
                        "ZipFile": (
                            "import boto3, os\n"
                            "sqs = boto3.client('sqs')\n"
                            "def handler(event, context):\n"
                            "    for rec in event.get('Records', []):\n"
                            "        sqs.send_message(QueueUrl=os.environ['SENTINEL_QUEUE_URL'], "
                            "MessageBody=rec['body'])\n"
                            "    return {'ok': True}\n"
                        )
                    },
                },
            },
            "EventSourceMapping": {
                "Type": "AWS::Lambda::EventSourceMapping",
                "Properties": {
                    "EventSourceArn": {"Fn::GetAtt": ["SourceQueue", "Arn"]},
                    "FunctionName": {"Ref": "Function"},
                    "BatchSize": 10,
                    "Enabled": True,
                    "FilterCriteria": {"Filters": [{"Pattern": filter_pattern}]},
                },
            },
        },
        "Outputs": {
            "SourceQueueUrl": {"Value": {"Ref": "SourceQueue"}},
            "SentinelQueueUrl": {"Value": {"Ref": "SentinelQueue"}},
            "FunctionName": {"Value": {"Ref": "Function"}},
            "EsmUuid": {"Value": {"Ref": "EventSourceMapping"}},
        },
    }

    result = _deploy_cfn(
        ctx,
        json.dumps(template),
        parameters={
            "RoleName": role_name,
            "SourceQueueName": source_queue_name,
            "SentinelQueueName": sentinel_queue_name,
            "FunctionName": function_name,
        },
    )
    source_url = result["outputs"]["SourceQueueUrl"]
    sentinel_url = result["outputs"]["SentinelQueueUrl"]
    esm_uuid = result["outputs"]["EsmUuid"]

    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_event_source_mapping(UUID=esm_uuid)["State"],
        lambda s: s == "Enabled",
        timeout_s=120, interval_s=3, description="event source mapping reaching Enabled",
    )

    sqs = ctx.client("sqs")
    matching_id = uuid.uuid4().hex
    ignored_id = uuid.uuid4().hex
    sqs.send_message(QueueUrl=source_url, MessageBody=json.dumps({"type": "important", "id": matching_id}))
    sqs.send_message(QueueUrl=source_url, MessageBody=json.dumps({"type": "ignored", "id": ignored_id}))

    # Only the matching message should ever reach the sentinel queue.
    seen_bodies: list[dict] = []

    def _probe_sentinel():
        r = sqs.receive_message(QueueUrl=sentinel_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for m in r.get("Messages", []):
            body = json.loads(m["Body"])
            seen_bodies.append(body)
            sqs.delete_message(QueueUrl=sentinel_url, ReceiptHandle=m["ReceiptHandle"])
        return len(seen_bodies)

    match_wait_start = time.monotonic()
    _poll_until(_probe_sentinel, lambda n: n >= 1, timeout_s=90, interval_s=3, description="matching message invoking Lambda")
    match_latency_s = time.monotonic() - match_wait_start

    # Bound the absence window against the positive control's own demonstrated latency on this
    # same wiring, not a guessed constant: a target slow enough to still be delivering the
    # matching message would otherwise score a "correct but slower" delivery path as blocked.
    absence_window_s = max(15.0, 3.0 * match_latency_s)
    deadline = time.monotonic() + absence_window_s
    while time.monotonic() < deadline:
        _probe_sentinel()
        time.sleep(3)

    assert len(seen_bodies) == 1, f"expected exactly one invocation-forwarded message, got {seen_bodies}"
    assert seen_bodies[0]["id"] == matching_id, f"expected forwarded message id {matching_id!r}, got {seen_bodies[0]['id']!r}"
    assert all(b["id"] != ignored_id for b in seen_bodies), f"filtered message {ignored_id!r} was forwarded to sentinel: {seen_bodies}"

    # Both messages are gone from the source queue: the matching one was processed+deleted, the
    # non-matching one was auto-discarded by the SQS event-filtering poller.
    def _source_empty():
        attrs = sqs.get_queue_attributes(
            QueueUrl=source_url,
            AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible"],
        )["Attributes"]
        return int(attrs["ApproximateNumberOfMessages"]) + int(attrs["ApproximateNumberOfMessagesNotVisible"])

    _poll_until(_source_empty, lambda n: n == 0, timeout_s=60, interval_s=3, description="source queue drained")


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
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError"):
                raise
            return 'GONE'

    _poll_until(
        _status, lambda s: s in {"DELETE_COMPLETE", "GONE"}, timeout_s=120, interval_s=5.0,
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
        timeout_s=timeout_s, interval_s=5.0, description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
