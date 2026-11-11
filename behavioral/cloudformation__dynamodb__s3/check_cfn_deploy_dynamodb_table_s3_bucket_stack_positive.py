"""cfn-deploy-dynamodb-table-s3-bucket-stack-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-dynamodb-table-s3-bucket-stack-positive"
GROUP = "deployment-order"
SERVICES = ["cloudformation", "dynamodb", "s3"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "plane:data")
def run(ctx) -> None:
    """A template with both AWS::DynamoDB::Table and AWS::S3::Bucket creates concrete,
    independently reachable resources in both services after CREATE_COMPLETE, and each
    resource's data plane actually works (not just a control-plane echo)."""
    table_name = _xname(ctx, "table")
    bucket_name = _xname(ctx, "bucket")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Table": {
                    "Type": "AWS::DynamoDB::Table",
                    "Properties": {
                        "TableName": table_name,
                        "BillingMode": "PAY_PER_REQUEST",
                        "AttributeDefinitions": [
                            {"AttributeName": "pk", "AttributeType": "S"}
                        ],
                        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                    },
                },
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"BucketName": bucket_name},
                },
            },
            "Outputs": {
                "TableName": {"Value": {"Ref": "Table"}},
                "BucketName": {"Value": {"Ref": "Bucket"}},
            },
        }
    )
    result = _deploy_cfn(ctx, template)
    out_table = result["outputs"]["TableName"]
    out_bucket = result["outputs"]["BucketName"]
    assert out_table == table_name, f"expected stack output TableName {table_name!r}, got {out_table!r}"
    assert out_bucket == bucket_name, f"expected stack output BucketName {bucket_name!r}, got {out_bucket!r}"

    dynamodb = ctx.client("dynamodb")
    desc = dynamodb.describe_table(TableName=out_table)["Table"]
    assert desc["TableStatus"] == "ACTIVE", (
        f"expected table {out_table} ACTIVE after CREATE_COMPLETE, got {desc['TableStatus']!r}"
    )

    s3 = ctx.client("s3")
    s3.head_bucket(Bucket=out_bucket)

    # Data-plane round trip on both, not just control-plane presence.
    dynamodb.put_item(TableName=out_table, Item={"pk": {"S": "row-1"}, "v": {"S": "hi"}})
    ctx.on_cleanup(lambda: dynamodb.delete_item(TableName=out_table, Key={"pk": {"S": "row-1"}}))
    item = dynamodb.get_item(TableName=out_table, Key={"pk": {"S": "row-1"}})["Item"]
    assert item["v"]["S"] == "hi", f"expected item row-1 v='hi', got {item.get('v')!r}"
    # The delete is already mandatory cleanup; make it a free negative too — an independent
    # read must show the item gone, not just that delete_item returned 200.
    dynamodb.delete_item(TableName=out_table, Key={"pk": {"S": "row-1"}})
    gone_item = dynamodb.get_item(TableName=out_table, Key={"pk": {"S": "row-1"}}).get("Item")
    assert gone_item is None, f"expected item row-1 deleted, still present: {gone_item!r}"

    s3.put_object(Bucket=out_bucket, Key="probe.txt", Body=b"hello-s3")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=out_bucket, Key="probe.txt"))
    body = s3.get_object(Bucket=out_bucket, Key="probe.txt")["Body"].read()
    assert body == b"hello-s3", f"expected probe.txt body b'hello-s3', got {body!r}"
    s3.delete_object(Bucket=out_bucket, Key="probe.txt")
    code = _expect_not_found(lambda: s3.head_object(Bucket=out_bucket, Key="probe.txt"))
    assert code == "404", f"expected probe.txt deleted (404 on head_object), got {code!r}"


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _expect_not_found(fn) -> str:
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    raise AssertionError("expected the read to fail with a not-found error, but it succeeded")


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
