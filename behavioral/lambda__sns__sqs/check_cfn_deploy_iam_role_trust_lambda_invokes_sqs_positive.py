"""cfn-deploy-iam-role-trust-lambda-invokes-sqs-positive."""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-iam-role-trust-lambda-invokes-sqs-positive"
GROUP = "deploy-iam-trust"
SERVICES = ["lambda", "sns", "sqs"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN stack that trusts lambda.amazonaws.com and grants sqs:SendMessage lets the
    deployed function actually send a message to the queue — not just describe as CREATE_COMPLETE."""
    role_name = _xname(ctx, "role")
    queue_name = _xname(ctx, "queue")
    function_name = _xname(ctx, "fn")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "RoleName": {"Type": "String"},
            "QueueName": {"Type": "String"},
            "FunctionName": {"Type": "String"},
        },
        "Resources": {
            "LambdaRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": {"Ref": "RoleName"},
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
                            "PolicyName": "SendToQueue",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["sqs:SendMessage"],
                                        "Resource": {"Fn::GetAtt": ["Queue", "Arn"]},
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
            "Queue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": {"Ref": "QueueName"}},
            },
            "Function": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": {"Ref": "FunctionName"},
                    "Role": {"Fn::GetAtt": ["LambdaRole", "Arn"]},
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Timeout": 15,
                    "Environment": {
                        "Variables": {"QUEUE_URL": {"Ref": "Queue"}}
                    },
                    "Code": {
                        "ZipFile": (
                            "import boto3, os\n"
                            "sqs = boto3.client('sqs')\n"
                            "def handler(event, context):\n"
                            "    sqs.send_message(QueueUrl=os.environ['QUEUE_URL'], "
                            "MessageBody=event.get('body', 'default'))\n"
                            "    return {'ok': True}\n"
                        )
                    },
                },
            },
        },
        "Outputs": {
            "QueueUrl": {"Value": {"Ref": "Queue"}},
            "FunctionName": {"Value": {"Ref": "Function"}},
        },
    }

    result = _deploy_cfn(
        ctx,
        json.dumps(template),
        parameters={
            "RoleName": role_name,
            "QueueName": queue_name,
            "FunctionName": function_name,
        },
    )
    queue_url = result["outputs"]["QueueUrl"]
    fn_name = result["outputs"]["FunctionName"]

    marker = f"hello-from-lambda-{uuid.uuid4().hex}"
    lam = ctx.client("lambda")

    def _invoke():
        return lam.invoke(
            FunctionName=fn_name,
            InvocationType="RequestResponse",
            Payload=json.dumps({"body": marker}).encode("utf-8"),
        )

    # IAM role trust may lag briefly right after CREATE_COMPLETE; retry the invoke itself.
    last_err = None
    resp = None
    for _ in range(10):
        try:
            resp = _invoke()
            if "FunctionError" not in resp:
                break
        except ClientError as e:
            last_err = e
        time.sleep(3)
    if resp is None:
        raise AssertionError(f"invoke never succeeded: {last_err}")
    assert "FunctionError" not in resp, f"lambda invocation failed: {resp}"

    sqs = ctx.client("sqs")

    def _probe():
        r = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=5, WaitTimeSeconds=5)
        for m in r.get("Messages", []):
            if m["Body"] == marker:
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
                return m
        return None

    found = _poll_until(_probe, lambda m: m is not None, timeout_s=60, interval_s=3, description="marker message in queue")
    assert found["Body"] == marker, f"expected marker {marker!r} in delivered message, got {found['Body']!r}"


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
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
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
