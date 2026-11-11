"""cfn-nested-stack-lambda-provider-reuse-positive."""
from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import urlsplit

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-nested-stack-lambda-provider-reuse-positive"
GROUP = "resource-binding"
SERVICES = ["apigateway", "cloudformation", "lambda"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A nested stack's custom resource reuses the parent's Lambda provider passed as a parameter: both
    stacks' outputs carry the values each call sent, and SQS receives exactly one invocation per call site."""
    bucket = _create_scratch_bucket(ctx)
    queue_url, queue_arn = _create_queue(ctx)
    s3 = ctx.client("s3")
    key = "nested-template.json"
    s3.put_object(Bucket=bucket, Key=key, Body=json.dumps(_nested_template()).encode())
    template_url = _presigned_get(ctx, s3, bucket, key)

    parent = _parent_template(template_url)
    result = _deploy_cfn(
        ctx,
        json.dumps(parent),
        parameters={"QueueArn": queue_arn, "QueueUrl": queue_url},
        timeout_s=420.0,
    )

    assert result["outputs"]["ParentRequestType"] == "Create", result["outputs"]
    assert result["outputs"]["ParentNewValue"] == "parent-value", result["outputs"]
    assert result["outputs"]["NestedRequestType"] == "Create", result["outputs"]
    assert result["outputs"]["NestedNewValue"] == "nested-value", result["outputs"]

    bodies = _receive_messages(ctx, queue_url, count=2, timeout_s=90.0)
    new_values = sorted(b["NewValue"] for b in bodies)
    assert new_values == ["nested-value", "parent-value"], (
        f"expected exactly one shared-provider invocation per call site, got {new_values!r}"
    )
    assert all(b["RequestType"] == "Create" for b in bodies), bodies

    extra = ctx.client("sqs").receive_message(
        QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=2
    ).get("Messages", [])
    assert extra == [], f"expected no further shared-provider invocations, got {extra!r}"


def _parent_template(template_url: str) -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "QueueArn": {"Type": "String"},
            "QueueUrl": {"Type": "String"},
        },
        "Resources": {
            "ExecRole": {
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
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                    "Policies": [
                        {
                            "PolicyName": "AllowSendToQueue",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "sqs:SendMessage",
                                        "Resource": {"Ref": "QueueArn"},
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "ProviderFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "Handler": "index.handler",
                    "Runtime": "python3.12",
                    "Timeout": 30,
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Code": {"ZipFile": {"Fn::Join": ["\n", _provider_code_lines()]}},
                },
            },
            "ParentResource": {
                "Type": "Custom::Sim2RealTest",
                "Properties": {
                    "ServiceToken": {"Fn::GetAtt": ["ProviderFunction", "Arn"]},
                    "QueueUrl": {"Ref": "QueueUrl"},
                    "Value": "parent-value",
                },
            },
            "NestedStack": {
                "Type": "AWS::CloudFormation::Stack",
                "Properties": {
                    "TemplateURL": template_url,
                    "Parameters": {
                        "ServiceToken": {"Fn::GetAtt": ["ProviderFunction", "Arn"]},
                        "QueueUrl": {"Ref": "QueueUrl"},
                        "Value": "nested-value",
                    },
                },
            },
        },
        "Outputs": {
            "ParentRequestType": {"Value": {"Fn::GetAtt": ["ParentResource", "RequestType"]}},
            "ParentNewValue": {"Value": {"Fn::GetAtt": ["ParentResource", "NewValue"]}},
            "NestedRequestType": {
                "Value": {"Fn::GetAtt": ["NestedStack", "Outputs.RequestType"]}
            },
            "NestedNewValue": {"Value": {"Fn::GetAtt": ["NestedStack", "Outputs.NewValue"]}},
        },
    }


def _nested_template() -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "ServiceToken": {"Type": "String"},
            "QueueUrl": {"Type": "String", "Default": ""},
            "Value": {"Type": "String", "Default": ""},
        },
        "Resources": {
            "NestedResource": {
                "Type": "Custom::Sim2RealTest",
                "Properties": {
                    "ServiceToken": {"Ref": "ServiceToken"},
                    "QueueUrl": {"Ref": "QueueUrl"},
                    "Value": {"Ref": "Value"},
                },
            }
        },
        "Outputs": {
            "RequestType": {"Value": {"Fn::GetAtt": ["NestedResource", "RequestType"]}},
            "NewValue": {"Value": {"Fn::GetAtt": ["NestedResource", "NewValue"]}},
        },
    }


def _provider_code_lines() -> list[str]:
    return [
        "import json",
        "import boto3",
        "import cfnresponse",
        "",
        "def handler(event, context):",
        "    props = event.get('ResourceProperties') or {}",
        "    old_props = event.get('OldResourceProperties') or {}",
        "    request_type = event['RequestType']",
        "    queue_url = props.get('QueueUrl') or old_props.get('QueueUrl')",
        "    if queue_url:",
        "        boto3.client('sqs').send_message(",
        "            QueueUrl=queue_url,",
        "            MessageBody=json.dumps({",
        "                'RequestType': request_type,",
        "                'OldValue': old_props.get('Value'),",
        "                'NewValue': props.get('Value'),",
        "            }),",
        "        )",
        "    if props.get('ForceFail') == 'true':",
        "        cfnresponse.send(event, context, cfnresponse.FAILED, {}, 'sim2real-cr-fixed')",
        "        return",
        "    data = {'RequestType': request_type, 'NewValue': str(props.get('Value', ''))}",
        "    cfnresponse.send(event, context, cfnresponse.SUCCESS, data, 'sim2real-cr-fixed')",
    ]


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


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=_xname(ctx, "q"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _receive_messages(ctx, queue_url: str, *, count: int, timeout_s: float) -> list[dict[str, Any]]:
    sqs = ctx.client("sqs")
    bodies: list[dict[str, Any]] = []

    def _probe():
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            bodies.append(json.loads(msg["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
        return bodies

    _poll_until(
        _probe, lambda b: len(b) >= count, timeout_s=timeout_s, interval_s=2.0,
        description=f"{count} shared-provider side-channel messages",
    )
    return bodies


def _create_scratch_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = _xname(ctx, "bkt").lower()
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=name, Key=o["Key"])
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
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
        timeout_s=180,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template,
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
            s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
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


def _presigned_get(ctx, s3, bucket: str, key: str) -> str:
    """A presigned GetObject URL signed for the object's own S3 URL."""
    target = urlsplit(ctx.s3_object_url(f"https://{bucket}.s3.amazonaws.com/{key}", bucket, key))

    def onto_object_url(request, **_) -> None:
        # The signature covers the host and path, so the URL is moved before it is signed.
        request.url = urlsplit(request.url)._replace(
            scheme=target.scheme, netloc=target.netloc, path=target.path
        ).geturl()

    s3.meta.events.register("before-sign.s3.GetObject", onto_object_url)
    try:
        return s3.generate_presigned_url(
            "get_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=3600
        )
    finally:
        s3.meta.events.unregister("before-sign.s3.GetObject", onto_object_url)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
