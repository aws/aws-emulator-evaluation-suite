"""cfn-deploy-glue-database-table-s3-stack-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-glue-database-table-s3-stack-positive"
GROUP = "deployment-order"
SERVICES = ["emr", "glue", "s3"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN stack creates an S3 bucket and a Glue database/table whose StorageDescriptor
    Location references that same-stack bucket; the table's location must resolve to the
    real bucket, and data placed at that location is visible through the S3 API."""
    s3 = ctx.client("s3")
    glue = ctx.client("glue")

    db_name = _glue_name(ctx, "db")
    table_name = _glue_name(ctx, "tbl")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Bucket": {"Type": "AWS::S3::Bucket"},
            "GlueDatabase": {
                "Type": "AWS::Glue::Database",
                "Properties": {
                    "CatalogId": {"Ref": "AWS::AccountId"},
                    "DatabaseInput": {"Name": db_name},
                },
            },
            "GlueTable": {
                "Type": "AWS::Glue::Table",
                "DependsOn": ["Bucket", "GlueDatabase"],
                "Properties": {
                    "CatalogId": {"Ref": "AWS::AccountId"},
                    "DatabaseName": db_name,
                    "TableInput": {
                        "Name": table_name,
                        "TableType": "EXTERNAL_TABLE",
                        "Parameters": {"classification": "csv"},
                        "StorageDescriptor": {
                            "Location": {"Fn::Sub": "s3://${Bucket}/data/"},
                            "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                            "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
                            "SerdeInfo": {
                                "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe",
                                "Parameters": {"field.delim": ","},
                            },
                            "Columns": [
                                {"Name": "id", "Type": "string"},
                                {"Name": "name", "Type": "string"},
                                {"Name": "value", "Type": "string"},
                            ],
                        },
                    },
                },
            },
        },
        "Outputs": {"BucketName": {"Value": {"Ref": "Bucket"}}},
    }

    result = _deploy_cfn(ctx, json.dumps(template))
    bucket = result["outputs"]["BucketName"]

    # The bucket referenced by the table's Location must be the one this stack created.
    s3.head_bucket(Bucket=bucket)

    body = b"1,alice,100\n2,bob,200\n"
    s3.put_object(Bucket=bucket, Key="data/part-00000.csv", Body=body)
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket))

    table = glue.get_table(DatabaseName=db_name, Name=table_name)["Table"]
    expected_location = f"s3://{bucket}/data/"
    actual_location = table["StorageDescriptor"]["Location"]
    assert actual_location == expected_location, (
        f"Glue table location expected {expected_location!r}, got {actual_location!r}"
    )

    listing = s3.list_objects_v2(Bucket=bucket, Prefix="data/")
    assert listing["KeyCount"] == 1, f"expected 1 object under data/, got {listing['KeyCount']}"
    actual_key = listing["Contents"][0]["Key"]
    assert actual_key == "data/part-00000.csv", (
        f"expected key 'data/part-00000.csv', got {actual_key!r}"
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


def _glue_name(ctx: Any, kind: str) -> str:
    """Glue database/table names should be lower-case with no hyphens (Athena-compatible)."""
    return _xname(ctx, kind).replace("-", "_")


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


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
