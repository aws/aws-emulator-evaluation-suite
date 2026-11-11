"""deploy-sam-lambda-secret-s3-dynamodb-full-stack."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sam-lambda-secret-s3-dynamodb-full-stack"
GROUP = "deployment-order"
SERVICES = ["dynamodb", "lambda", "s3", "secretsmanager"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """In a SAM-transform stack, uploading an object to the bucket invokes the function through the bucket
    notification, and it writes the secret's value and the bucket name to the table.
    """
    suffix = ctx.unique_name("sim2real-xsvc-samfull-")
    secret_string = json.dumps({"apiKey": f"value-{suffix[-12:]}"})

    code = (
        "import json\n"
        "import os\n\n"
        "import boto3\n\n\n"
        "def handler(event, context):\n"
        "    sm = boto3.client('secretsmanager')\n"
        "    ddb = boto3.client('dynamodb')\n"
        "    secret = sm.get_secret_value(SecretId=os.environ['SECRET_ARN'])['SecretString']\n"
        "    for record in event.get('Records', []):\n"
        "        key = record['s3']['object']['key']\n"
        "        bucket = record['s3']['bucket']['name']\n"
        "        ddb.put_item(\n"
        "            TableName=os.environ['TABLE_NAME'],\n"
        "            Item={'pk': {'S': key}, 'secret': {'S': secret}, 'bucket': {'S': bucket}},\n"
        "        )\n"
        "    return {'status': 'ok'}\n"
    )
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Transform": "AWS::Serverless-2016-10-31",
        "Resources": {
            "MySecret": {
                "Type": "AWS::SecretsManager::Secret",
                "Properties": {"SecretString": secret_string},
            },
            "MyTable": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "BillingMode": "PAY_PER_REQUEST",
                    "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                },
            },
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
                            "PolicyName": "access",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": "secretsmanager:GetSecretValue",
                                        "Resource": {"Ref": "MySecret"},
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": "dynamodb:PutItem",
                                        "Resource": {"Fn::GetAtt": ["MyTable", "Arn"]},
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "Fn": {
                "Type": "AWS::Serverless::Function",
                "Properties": {
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Timeout": 15,
                    "InlineCode": code,
                    "Environment": {
                        "Variables": {
                            "SECRET_ARN": {"Ref": "MySecret"},
                            "TABLE_NAME": {"Ref": "MyTable"},
                        }
                    },
                },
            },
            "FnPermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "FunctionName": {"Ref": "Fn"},
                    "Action": "lambda:InvokeFunction",
                    "Principal": "s3.amazonaws.com",
                    "SourceAccount": {"Ref": "AWS::AccountId"},
                },
            },
            "MyBucket": {
                "Type": "AWS::S3::Bucket",
                "DependsOn": "FnPermission",
                "Properties": {
                    "NotificationConfiguration": {
                        "LambdaConfigurations": [
                            {
                                "Event": "s3:ObjectCreated:*",
                                "Function": {"Fn::GetAtt": ["Fn", "Arn"]},
                            }
                        ]
                    }
                },
            },
        },
        "Outputs": {
            "BucketName": {"Value": {"Ref": "MyBucket"}},
            "TableName": {"Value": {"Ref": "MyTable"}},
            "SecretArn": {"Value": {"Ref": "MySecret"}},
        },
    }

    result = _deploy_cfn(
        ctx,
        json.dumps(template),
        capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"],
    )
    bucket = result["outputs"]["BucketName"]
    table = result["outputs"]["TableName"]

    s3 = ctx.client("s3")
    ddb = ctx.client("dynamodb")
    key = "incoming/file1.txt"
    s3.put_object(Bucket=bucket, Key=key, Body=b"hello-sam")

    item = _poll_until(
        lambda: ddb.get_item(TableName=table, Key={"pk": {"S": key}}).get("Item"),
        lambda it: it is not None,
        timeout_s=120.0,
        interval_s=4.0,
        description="s3 upload triggers lambda which writes secret+bucket into dynamodb",
    )
    assert item["secret"]["S"] == secret_string, f"expected secret {secret_string!r}, got {item['secret']['S']!r}"
    assert item["bucket"]["S"] == bucket, f"expected bucket {bucket!r}, got {item['bucket']['S']!r}"

    # CloudFormation cannot delete a non-empty S3 bucket: the object put above would
    # leave the stack in DELETE_FAILED, leaking the bucket, table, secret and role.
    # Emptying it here lets the stack's delete succeed.
    for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])


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
