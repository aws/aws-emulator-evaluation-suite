"""deploy-cfn-stack-update-glue-table-schema-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-stack-update-glue-table-schema-positive"
GROUP = "deployment-order"
SERVICES = ["athena", "glue", "s3"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Updating the CFN stack to add a Glue table column is reflected via glue.get_table
    without disturbing the underlying S3 data location."""
    bucket_name = _xname(ctx, "schemaupd-bkt")
    db_name = _sql_name(ctx, "schemaupddb")
    table_name = _sql_name(ctx, "schemaupdtbl")

    def _template(columns: list[dict[str, str]]) -> str:
        return json.dumps(
            {
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
                                    "Location": f"s3://{bucket_name}/data/",
                                    "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
                                    "OutputFormat": (
                                        "org.apache.hadoop.hive.ql.io."
                                        "HiveIgnoreKeyTextOutputFormat"
                                    ),
                                    "SerdeInfo": {
                                        "SerializationLibrary": (
                                            "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
                                        ),
                                        "Parameters": {"field.delim": ","},
                                    },
                                    "Columns": columns,
                                },
                            },
                        },
                    },
                },
            }
        )

    v1_columns = [{"Name": "id", "Type": "int"}, {"Name": "name", "Type": "string"}]
    deploy = _deploy_cfn(ctx, _template(v1_columns))
    stack_name = deploy["stack_name"]

    glue = ctx.client("glue")
    table_v1 = glue.get_table(DatabaseName=db_name, Name=table_name)["Table"]
    v1_names = [c["Name"] for c in table_v1["StorageDescriptor"]["Columns"]]
    assert v1_names == ["id", "name"], v1_names

    v2_columns = v1_columns + [{"Name": "status", "Type": "string"}]
    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=_template(v2_columns),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    terminal = {
        "UPDATE_COMPLETE",
        "UPDATE_ROLLBACK_COMPLETE",
        "UPDATE_FAILED",
        "UPDATE_ROLLBACK_FAILED",
    }
    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in terminal,
        timeout_s=180,
        interval_s=5.0,
        description=f"stack update {stack_name} terminal",
    )
    assert status == "UPDATE_COMPLETE", status

    table_v2 = glue.get_table(DatabaseName=db_name, Name=table_name)["Table"]
    assert [c["Name"] for c in table_v2["StorageDescriptor"]["Columns"]] == [
        "id",
        "name",
        "status",
    ], table_v2["StorageDescriptor"]["Columns"]
    v2_location = table_v2["StorageDescriptor"]["Location"]
    assert v2_location == f"s3://{bucket_name}/data/", v2_location


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
