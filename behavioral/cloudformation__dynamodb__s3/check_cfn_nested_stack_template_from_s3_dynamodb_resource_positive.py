"""cfn-nested-stack-template-from-s3-dynamodb-resource-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-nested-stack-template-from-s3-dynamodb-resource-positive"
GROUP = "resource-binding"
SERVICES = ["cloudformation", "dynamodb", "s3"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:e2e", "plane:control")
def run(ctx) -> None:
    """A parent stack's AWS::CloudFormation::Stack resource with a TemplateURL in S3 provisions the
    DynamoDB table the nested template declares: the nested stack names the table and DynamoDB
    reports it ACTIVE, so CloudFormation fetched and executed the S3-hosted body."""
    s3 = ctx.client("s3")
    bucket_name = _xname(ctx, "tmplbucket")
    key = "nested/dynamo-table.json"
    table_name = _xname(ctx, "nested-table")

    s3.create_bucket(**_create_bucket_kwargs(ctx, bucket_name))
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket_name))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": _xsvc_tags_kv()})
    nested_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "NestedTable": {
                    "Type": "AWS::DynamoDB::Table",
                    "Properties": {
                        "TableName": table_name,
                        "BillingMode": "PAY_PER_REQUEST",
                        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                    },
                }
            },
            "Outputs": {"TableName": {"Value": {"Ref": "NestedTable"}}},
        }
    )
    s3.put_object(Bucket=bucket_name, Key=key, Body=nested_template.encode())

    template_url = f"https://{bucket_name}.s3.{ctx.region}.amazonaws.com/{key}"
    parent_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "NestedStack": {
                    "Type": "AWS::CloudFormation::Stack",
                    "Properties": {"TemplateURL": template_url, "TimeoutInMinutes": 10},
                }
            },
            "Outputs": {
                "NestedTableName": {"Value": {"Fn::GetAtt": ["NestedStack", "Outputs.TableName"]}}
            },
        }
    )
    result = _deploy_cfn(ctx, parent_template)
    nested_table_name = result["outputs"]["NestedTableName"]
    assert nested_table_name == table_name, (
        f"parent stack output NestedTableName expected {table_name!r} "
        f"(the nested template's own TableName property), got {nested_table_name!r}"
    )

    dynamodb = ctx.client("dynamodb")
    desc = dynamodb.describe_table(TableName=nested_table_name)["Table"]
    assert desc["TableStatus"] == "ACTIVE", (
        f"table {nested_table_name!r} provisioned by the S3-hosted nested template "
        f"expected TableStatus ACTIVE, got {desc['TableStatus']!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _create_bucket_kwargs(ctx, bucket_name: str) -> dict[str, Any]:
    kwargs: dict[str, Any] = {"Bucket": bucket_name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    return kwargs


def _empty_and_delete_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    try:
        objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        for obj in objs:
            s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise


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
