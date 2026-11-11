"""cfn-deploy-lambda-destination-sns-on-failure."""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-lambda-destination-sns-on-failure"
GROUP = "deploy-destinations"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed Lambda with an async OnFailure destination pointing at an SNS topic
    actually delivers an invocation-record notification (with the real error + payload) to that
    topic when a forced, always-failing async invocation exhausts its retries."""
    role_name = _xname(ctx, "role")
    topic_name = _xname(ctx, "topic")
    queue_name = _xname(ctx, "obsq")
    function_name = _xname(ctx, "fn")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "RoleName": {"Type": "String"},
            "TopicName": {"Type": "String"},
            "QueueName": {"Type": "String"},
            "FunctionName": {"Type": "String"},
        },
        "Resources": {
            "Topic": {"Type": "AWS::SNS::Topic", "Properties": {"TopicName": {"Ref": "TopicName"}}},
            "Queue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": {"Ref": "QueueName"}}},
            "QueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "Queue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "sns.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
                                "Condition": {"ArnEquals": {"aws:SourceArn": {"Ref": "Topic"}}},
                            }
                        ],
                    },
                },
            },
            "Subscription": {
                "Type": "AWS::SNS::Subscription",
                "Properties": {
                    "TopicArn": {"Ref": "Topic"},
                    "Protocol": "sqs",
                    "Endpoint": {"Fn::GetAtt": ["Queue", "Arn"]},
                },
                "DependsOn": "QueuePolicy",
            },
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
                            "PolicyName": "PublishFailures",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {"Effect": "Allow", "Action": "sns:Publish", "Resource": {"Ref": "Topic"}},
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
                    "Timeout": 10,
                    "Code": {
                        "ZipFile": (
                            "def handler(event, context):\n"
                            "    raise RuntimeError('forced failure: ' + event.get('marker', ''))\n"
                        )
                    },
                },
            },
            "EventInvokeConfig": {
                "Type": "AWS::Lambda::EventInvokeConfig",
                "Properties": {
                    "FunctionName": {"Ref": "Function"},
                    "Qualifier": "$LATEST",
                    "MaximumRetryAttempts": 0,
                    "DestinationConfig": {"OnFailure": {"Destination": {"Ref": "Topic"}}},
                },
            },
        },
        "Outputs": {
            "TopicArn": {"Value": {"Ref": "Topic"}},
            "QueueUrl": {"Value": {"Ref": "Queue"}},
            "FunctionName": {"Value": {"Ref": "Function"}},
        },
    }

    result = _deploy_cfn(
        ctx,
        json.dumps(template),
        parameters={
            "RoleName": role_name,
            "TopicName": topic_name,
            "QueueName": queue_name,
            "FunctionName": function_name,
        },
    )
    fn_name = result["outputs"]["FunctionName"]
    queue_url = result["outputs"]["QueueUrl"]

    marker = uuid.uuid4().hex
    lam = ctx.client("lambda")

    # Retry the async invoke call itself for IAM-propagation lag; the invocation always fails
    # inside the function, that part is intentional.
    for attempt in range(10):
        try:
            resp = lam.invoke(
                FunctionName=fn_name,
                InvocationType="Event",
                Payload=json.dumps({"marker": marker}).encode("utf-8"),
            )
            assert resp["StatusCode"] == 202, f"expected async Invoke to accept with 202, got {resp['StatusCode']}"
            break
        except ClientError:
            if attempt == 9:
                raise
            time.sleep(3)

    sqs = ctx.client("sqs")

    def _probe():
        r = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=5, WaitTimeSeconds=5)
        for m in r.get("Messages", []):
            try:
                envelope = json.loads(m["Body"])
                record = json.loads(envelope["Message"])
            except (json.JSONDecodeError, ValueError, KeyError):
                continue
            if record.get("requestPayload", {}).get("marker") == marker:
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
                return record
        return None

    record = _poll_until(
        _probe, lambda r: r is not None, timeout_s=90, interval_s=4,
        description="failure-destination invocation record on SNS-fed queue",
    )
    assert record["requestPayload"]["marker"] == marker, (
        f"expected delivered invocation record to echo marker {marker!r}, "
        f"got requestPayload {record['requestPayload']!r}"
    )
    assert record["requestContext"]["condition"] == "RetriesExhausted", (
        f"expected requestContext.condition 'RetriesExhausted' after MaximumRetryAttempts=0 exhausted "
        f"retries, got {record['requestContext']['condition']!r}"
    )
    assert "forced failure" in record["responsePayload"]["errorMessage"], (
        f"expected responsePayload.errorMessage to contain 'forced failure', "
        f"got {record['responsePayload']['errorMessage']!r}"
    )


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
