"""deploy-s3-batch-notification-multiple-lambda-targets-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-s3-batch-notification-multiple-lambda-targets-positive"
GROUP = "deployment-order"
SERVICES = ["lambda", "s3", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A deployed CFN stack with two prefix-scoped S3 notification rules on one bucket invokes
    the distinct Lambda function wired to each prefix, and only that one."""
    bucket_name = ctx.unique_name("sim2real-xsvc-bkt-").lower()
    fn_a_name = ctx.unique_name("sim2real-xsvc-fn-a-")
    fn_b_name = ctx.unique_name("sim2real-xsvc-fn-b-")
    template = _build_template(bucket_name, fn_a_name, fn_b_name)
    stack = _deploy_cfn(ctx, template, parameters={"BucketNameParam": bucket_name})

    s3 = ctx.client("s3")
    ctx.on_cleanup(lambda: _empty_bucket(s3, bucket_name))

    queue_a_url = stack["outputs"]["QueueAUrl"]
    queue_b_url = stack["outputs"]["QueueBUrl"]

    s3.put_object(Bucket=bucket_name, Key="a/hello.txt", Body=b"payload-a")
    s3.put_object(Bucket=bucket_name, Key="b/hello.txt", Body=b"payload-b")

    sqs = ctx.client("sqs")
    msg_a = _poll_until(
        lambda: _receive_one(sqs, queue_a_url),
        lambda m: m is not None,
        timeout_s=90,
        interval_s=3.0,
        description="notification for prefix a/ on QueueA",
    )
    msg_b = _poll_until(
        lambda: _receive_one(sqs, queue_b_url),
        lambda m: m is not None,
        timeout_s=90,
        interval_s=3.0,
        description="notification for prefix b/ on QueueB",
    )
    body_a = json.loads(msg_a["Body"])["key"]
    assert body_a == "a/hello.txt", f"QueueA (prefix a/) expected key a/hello.txt, got {body_a}"
    body_b = json.loads(msg_b["Body"])["key"]
    assert body_b == "b/hello.txt", f"QueueB (prefix b/) expected key b/hello.txt, got {body_b}"

    # Cross-routing check: QueueA must never see the b/ event and vice versa.
    stray_a = _receive_one(sqs, queue_a_url, wait_s=5)
    stray_b = _receive_one(sqs, queue_b_url, wait_s=5)
    assert stray_a is None, f"QueueA (prefix a/) unexpectedly received: {stray_a}"
    assert stray_b is None, f"QueueB (prefix b/) unexpectedly received: {stray_b}"


def _receive_one(sqs, queue_url, wait_s=5):
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=wait_s)
    msgs = resp.get("Messages", [])
    if not msgs:
        return None
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msgs[0]["ReceiptHandle"])
    return msgs[0]


def _empty_bucket(s3, bucket_name: str) -> None:
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            objs = page.get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket_name,
                    Delete={"Objects": [{"Key": o["Key"]} for o in objs]},
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


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


def _build_template(bucket_name: str, fn_a_name: str, fn_b_name: str) -> str:
    def notifier_code(env_var: str) -> str:
        return (
            "import json, os, boto3\n"
            "sqs = boto3.client('sqs')\n"
            f"QUEUE_URL = os.environ['{env_var}']\n"
            "def handler(event, context):\n"
            "    for r in event['Records']:\n"
            "        key = r['s3']['object']['key']\n"
            "        sqs.send_message(QueueUrl=QUEUE_URL, MessageBody=json.dumps({'key': key}))\n"
        )

    def role_and_fn(letter: str, fn_name: str, queue_logical: str, env_var: str) -> dict:
        role_logical = f"Role{letter}"
        return {
            role_logical: {
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
                                        "Action": "sqs:SendMessage",
                                        "Resource": {"Fn::GetAtt": [queue_logical, "Arn"]},
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            f"Function{letter}": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": fn_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": [role_logical, "Arn"]},
                    "Timeout": 10,
                    "Environment": {"Variables": {env_var: {"Ref": queue_logical}}},
                    "Code": {"ZipFile": notifier_code(env_var)},
                },
            },
            f"Permission{letter}": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "FunctionName": {"Ref": f"Function{letter}"},
                    "Action": "lambda:InvokeFunction",
                    "Principal": "s3.amazonaws.com",
                    "SourceArn": {"Fn::Sub": f"arn:aws:s3:::{bucket_name}"},
                    "SourceAccount": {"Ref": "AWS::AccountId"},
                },
            },
        }

    resources: dict = {
        "QueueA": {"Type": "AWS::SQS::Queue"},
        "QueueB": {"Type": "AWS::SQS::Queue"},
    }
    resources.update(role_and_fn("A", fn_a_name, "QueueA", "QUEUE_URL_A"))
    resources.update(role_and_fn("B", fn_b_name, "QueueB", "QUEUE_URL_B"))
    resources["Bucket"] = {
        "Type": "AWS::S3::Bucket",
        "DependsOn": ["PermissionA", "PermissionB"],
        "Properties": {
            "BucketName": {"Ref": "BucketNameParam"},
            "NotificationConfiguration": {
                "LambdaConfigurations": [
                    {
                        "Event": "s3:ObjectCreated:*",
                        "Function": {"Fn::GetAtt": ["FunctionA", "Arn"]},
                        "Filter": {
                            "S3Key": {"Rules": [{"Name": "prefix", "Value": "a/"}]}
                        },
                    },
                    {
                        "Event": "s3:ObjectCreated:*",
                        "Function": {"Fn::GetAtt": ["FunctionB", "Arn"]},
                        "Filter": {
                            "S3Key": {"Rules": [{"Name": "prefix", "Value": "b/"}]}
                        },
                    },
                ]
            },
        },
    }
    doc = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"BucketNameParam": {"Type": "String"}},
        "Resources": resources,
        "Outputs": {
            "QueueAUrl": {"Value": {"Ref": "QueueA"}},
            "QueueBUrl": {"Value": {"Ref": "QueueB"}},
        },
    }
    return json.dumps(doc)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
