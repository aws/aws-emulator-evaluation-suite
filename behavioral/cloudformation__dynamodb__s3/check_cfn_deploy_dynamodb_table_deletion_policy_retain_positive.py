"""cfn-deploy-dynamodb-table-deletion-policy-retain-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-dynamodb-table-deletion-policy-retain-positive"
GROUP = "resource-lifecycle"
SERVICES = ["cloudformation", "dynamodb", "s3"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """DeletionPolicy: Retain on a DynamoDB table keeps the live table intact in DynamoDB
    after the owning stack is deleted -- CloudFormation must skip the delete-table call for
    that logical resource specifically, not merely report success."""
    table_name = _xname(ctx, "table")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Table": {
                    "Type": "AWS::DynamoDB::Table",
                    "DeletionPolicy": "Retain",
                    "Properties": {
                        "TableName": table_name,
                        "BillingMode": "PAY_PER_REQUEST",
                        "AttributeDefinitions": [
                            {"AttributeName": "pk", "AttributeType": "S"}
                        ],
                        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                    },
                }
            },
            "Outputs": {"TableName": {"Value": {"Ref": "Table"}}},
        }
    )
    result = _deploy_cfn(ctx, template)
    out_table = result["outputs"]["TableName"]
    assert out_table == table_name, f"stack output TableName expected {table_name!r}, got {out_table!r}"

    dynamodb = ctx.client("dynamodb")
    desc = dynamodb.describe_table(TableName=out_table)["Table"]
    assert desc["TableStatus"] == "ACTIVE", f"table {out_table} expected status ACTIVE, got {desc['TableStatus']!r}"

    # Delete the owning stack now (also already scheduled via cleanup; calling it directly
    # here lets us assert on the retained table's live state right after deletion).
    _delete_stack_and_wait(ctx, result["stack_name"])

    # The table must still be describable and ACTIVE -- Retain means CFN never called
    # DeleteTable for this logical resource.
    desc_after = dynamodb.describe_table(TableName=out_table)["Table"]
    assert desc_after["TableStatus"] == "ACTIVE", (
        f"table {out_table} expected status ACTIVE after stack delete (Retain), "
        f"got {desc_after['TableStatus']!r}"
    )
    assert desc_after["TableName"] == table_name, (
        f"table expected name {table_name!r} after stack delete, got {desc_after['TableName']!r}"
    )

    # The table was never removed by the stack, so we must clean it up ourselves.
    ctx.on_cleanup(lambda: dynamodb.delete_table(TableName=out_table))


# ===== helpers =====
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
            if "does not exist" not in str(exc):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=2.0,
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
