"""cfn-cross-stack-export-dynamodb-table-name-to-s3-stack-negative."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-cross-stack-export-dynamodb-table-name-to-s3-stack-negative"
GROUP = "overly-permissive"
SERVICES = ["cloudformation", "dynamodb", "s3"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Fn::ImportValue of an undeclared DynamoDB table-name export fails the stack CREATE instead
    of resolving to an empty value; importing a real export succeeds and tags the S3 bucket with
    the imported table name."""
    # --- Exporter stack: a DynamoDB table whose name is exported under a unique name. ---
    table_name = _xname(ctx, "table")
    export_name = ctx.unique_name("sim2real-xsvc-export-")
    exporter_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Table": {
                    "Type": "AWS::DynamoDB::Table",
                    "Properties": {
                        "TableName": table_name,
                        "BillingMode": "PAY_PER_REQUEST",
                        "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                    },
                }
            },
            "Outputs": {
                "TableName": {
                    "Value": {"Ref": "Table"},
                    "Export": {"Name": export_name},
                }
            },
        }
    )
    exporter = _deploy_cfn(ctx, exporter_template)
    assert exporter["outputs"]["TableName"] == table_name, (
        f"exporter stack output TableName: expected {table_name!r}, got "
        f"{exporter['outputs'].get('TableName')!r}"
    )

    # --- Positive control: importer stack that consumes the REAL export. ---
    good_bucket_name = _xname(ctx, "bucket-good")
    good_importer_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": good_bucket_name,
                        "Tags": [
                            {"Key": "SourceTable", "Value": {"Fn::ImportValue": export_name}}
                        ],
                    },
                }
            },
        }
    )
    good_importer = _deploy_cfn(ctx, good_importer_template)
    s3 = ctx.client("s3")
    tags = {
        t["Key"]: t["Value"]
        for t in s3.get_bucket_tagging(Bucket=good_bucket_name)["TagSet"]
    }
    assert tags["SourceTable"] == table_name, (
        f"good importer bucket tag SourceTable: expected {table_name!r}, got "
        f"{tags.get('SourceTable')!r}"
    )
    # good_importer's own stack cleanup (already registered by _deploy_cfn) deletes this
    # empty bucket when the stack is torn down -- no separate bucket cleanup needed.
    # positive control: the bucket exists after a successful import (HeadBucket raises if not).
    s3.head_bucket(Bucket=good_bucket_name)

    # --- Negative: importer stack referencing an export that was never declared. ---
    bad_export_name = ctx.unique_name("sim2real-xsvc-export-never-declared-")
    bad_bucket_name = _xname(ctx, "bucket-bad")
    bad_importer_template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": bad_bucket_name,
                        "Tags": [
                            {"Key": "SourceTable", "Value": {"Fn::ImportValue": bad_export_name}}
                        ],
                    },
                }
            },
        }
    )
    cfn = ctx.client("cloudformation")
    bad_stack_name = _xname(ctx, "stk-bad")
    cfn.create_stack(
        StackName=bad_stack_name,
        TemplateBody=bad_importer_template,
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, bad_stack_name))
    final_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=bad_stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=180,
        interval_s=5.0,
        description=f"CFN stack {bad_stack_name} terminal status",
    )
    # (a) the stack must not have created successfully.
    assert final_status == "ROLLBACK_COMPLETE", (
        f"stack referencing a never-declared export: expected ROLLBACK_COMPLETE, got "
        f"{final_status!r}"
    )

    events = cfn.describe_stack_events(StackName=bad_stack_name)["StackEvents"]
    reasons = " | ".join(e.get("ResourceStatusReason", "") for e in events)
    assert "No export named" in reasons and bad_export_name in reasons, (
        f"expected a 'No export named ... {bad_export_name}' rollback reason, got: {reasons!r}"
    )

    # (b) the effect is absent: the bucket the failed stack would have created never exists.
    code = _error_code(lambda: s3.head_bucket(Bucket=bad_bucket_name))
    assert code == "404", (
        f"bucket {bad_bucket_name!r} from the rolled-back stack: expected head_bucket to "
        f"404, got error code {code!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"]
    raise AssertionError("the call was expected to be rejected but it succeeded")


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
