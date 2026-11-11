"""cfn-stack-update-dynamodb-table-billing-mode-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-stack-update-dynamodb-table-billing-mode-positive"
GROUP = "deployment-order"
SERVICES = ["cloudformation", "dynamodb", "s3"]


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An UpdateStack flipping a DynamoDB table from PROVISIONED (5 RCU) to PAY_PER_REQUEST shows in
    DescribeTable after UPDATE_COMPLETE with the same TableArn; an item written before the update
    survives it, and a write after it reads back."""
    table_name = _xname(ctx, "table")

    def _template(billing_mode: str) -> str:
        props: dict[str, Any] = {
            "TableName": table_name,
            "BillingMode": billing_mode,
            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
        }
        if billing_mode == "PROVISIONED":
            props["ProvisionedThroughput"] = {"ReadCapacityUnits": 5, "WriteCapacityUnits": 5}
        return json.dumps(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Resources": {"Table": {"Type": "AWS::DynamoDB::Table", "Properties": props}},
                "Outputs": {"TableName": {"Value": {"Ref": "Table"}}},
            }
        )

    result = _deploy_cfn(ctx, _template("PROVISIONED"))
    dynamodb = ctx.client("dynamodb")
    before = dynamodb.describe_table(TableName=table_name)["Table"]
    # DynamoDB only populates BillingModeSummary once a table has ever been PAY_PER_REQUEST
    # (or explicitly set) — a freshly-created PROVISIONED table may omit the field entirely,
    # so treat "absent" as PROVISIONED and confirm via ProvisionedThroughput instead.
    before_mode = before.get("BillingModeSummary", {}).get("BillingMode", "PROVISIONED")
    assert before_mode == "PROVISIONED", f"expected freshly-created table billing mode PROVISIONED, got {before_mode!r}"
    before_rcu = before["ProvisionedThroughput"]["ReadCapacityUnits"]
    assert before_rcu == 5, f"expected ReadCapacityUnits 5, got {before_rcu}"
    table_arn = before["TableArn"]

    dynamodb.put_item(TableName=table_name, Item={"pk": {"S": "k1"}, "v": {"S": "pre-update"}})

    _update_stack_and_wait(ctx, result["stack_name"], _template("PAY_PER_REQUEST"))

    after = dynamodb.describe_table(TableName=table_name)["Table"]
    after_mode = after["BillingModeSummary"]["BillingMode"]
    assert after_mode == "PAY_PER_REQUEST", f"expected settled billing mode PAY_PER_REQUEST, got {after_mode!r}"
    # Same physical resource, not a replacement.
    after_arn = after["TableArn"]
    assert after_arn == table_arn, f"expected TableArn to persist across the update ({table_arn!r}), got {after_arn!r}"

    # A replacement would have lost this item; a mode switch must not.
    survived = dynamodb.get_item(TableName=table_name, Key={"pk": {"S": "k1"}}, ConsistentRead=True)["Item"]["v"]["S"]
    assert survived == "pre-update", f"expected pre-update item to survive the billing-mode switch, got {survived!r}"

    # The data plane must remain fully usable under the new billing mode, not just describable.
    dynamodb.put_item(TableName=table_name, Item={"pk": {"S": "k2"}, "v": {"S": "post-update"}})
    wrote = dynamodb.get_item(TableName=table_name, Key={"pk": {"S": "k2"}}, ConsistentRead=True)["Item"]["v"]["S"]
    assert wrote == "post-update", f"expected post-update write to read back 'post-update', got {wrote!r}"


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


def _update_stack_and_wait(ctx, stack_name: str, template: str, *, timeout_s: float = 300.0) -> dict[str, Any]:
    """UpdateStack + poll to a terminal UPDATE_* status; asserts UPDATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=template,
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    final_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s
        in {
            "UPDATE_COMPLETE",
            "UPDATE_FAILED",
            "UPDATE_ROLLBACK_COMPLETE",
            "UPDATE_ROLLBACK_FAILED",
        },
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack update {stack_name}",
    )
    if final_status != "UPDATE_COMPLETE":
        raise AssertionError(f"Stack update {stack_name} ended in {final_status}")
    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": stack_name, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
