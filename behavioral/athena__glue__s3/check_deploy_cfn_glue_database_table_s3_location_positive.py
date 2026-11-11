"""deploy-cfn-glue-database-table-s3-location-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-glue-database-table-s3-location-positive"
GROUP = "deployment-order"
SERVICES = ["athena", "glue", "s3"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A deployed CFN stack's Glue database/table Location resolves to the stack's S3 bucket."""
    bucket_name = _xname(ctx, "gluetbl-bkt")
    db_name = _sql_name(ctx, "gluetbldb")
    table_name = _sql_name(ctx, "gluetbltbl")

    template = {
        "Resources": {
            "DataBucket": {
                "Type": "AWS::S3::Bucket",
                "Properties": {"BucketName": bucket_name, "Tags": _xsvc_tags_kv()},
            },
            "GlueDatabase": {
                "Type": "AWS::Glue::Database",
                "Properties": {
                    "CatalogId": {"Ref": "AWS::AccountId"},
                    "DatabaseInput": {"Name": db_name},
                },
            },
            "GlueTable": {
                "Type": "AWS::Glue::Table",
                "DependsOn": ["GlueDatabase", "DataBucket"],
                "Properties": {
                    "CatalogId": {"Ref": "AWS::AccountId"},
                    "DatabaseName": {"Ref": "GlueDatabase"},
                    "TableInput": {
                        "Name": table_name,
                        "TableType": "EXTERNAL_TABLE",
                        "Parameters": {"classification": "csv"},
                        "StorageDescriptor": {
                            "Location": {"Fn::Sub": "s3://${DataBucket}/data/"},
                            "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                            "OutputFormat": (
                                "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"
                            ),
                            "SerdeInfo": {
                                "SerializationLibrary": (
                                    "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
                                ),
                                "Parameters": {"field.delim": ","},
                            },
                            "Columns": [
                                {"Name": "id", "Type": "int"},
                                {"Name": "name", "Type": "string"},
                            ],
                        },
                    },
                },
            },
        },
    }

    _deploy_cfn(ctx, json.dumps(template))

    glue = ctx.client("glue")
    table = glue.get_table(DatabaseName=db_name, Name=table_name)["Table"]
    location = table["StorageDescriptor"]["Location"]
    assert location == f"s3://{bucket_name}/data/", location

    s3 = ctx.client("s3")
    s3.head_bucket(Bucket=bucket_name)  # bucket the table's Location resolves to really exists


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


def _sql_name(ctx: Any, kind: str) -> str:
    """A Glue/Athena-identifier-safe unique name (underscores, no hyphens)."""
    return _xname(ctx, kind).replace("-", "_")


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


def _deploy_cfn(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
) -> dict[str, Any]:
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
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s
        in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
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
