"""cfn-stack-policy-protects-dynamodb-table-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-stack-policy-protects-dynamodb-table-positive"
GROUP = "resource-lifecycle"
SERVICES = ["cloudformation", "dynamodb", "s3"]


@tags("axis:rejection", "cap:c3", "cap:c4", "cap:c7", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack policy denying Update:* on a DynamoDB table blocks a stack update of its
    throughput; removing that restriction lets the identical update through to the live table."""
    table_name = _xname(ctx, "table")

    def _template(read_capacity: int) -> str:
        return json.dumps(
            {
                "AWSTemplateFormatVersion": "2010-09-09",
                "Resources": {
                    "Table": {
                        "Type": "AWS::DynamoDB::Table",
                        "Properties": {
                            "TableName": table_name,
                            "BillingMode": "PROVISIONED",
                            "ProvisionedThroughput": {
                                "ReadCapacityUnits": read_capacity,
                                "WriteCapacityUnits": 5,
                            },
                            "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                            "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                        },
                    }
                },
            }
        )

    result = _deploy_cfn(ctx, _template(5))
    stack_name = result["stack_name"]
    dynamodb = ctx.client("dynamodb")
    before = dynamodb.describe_table(TableName=table_name)["Table"]
    before_rcu = before["ProvisionedThroughput"]["ReadCapacityUnits"]
    assert before_rcu == 5, f"table {table_name} should deploy with ReadCapacityUnits=5, got {before_rcu}"

    cfn = ctx.client("cloudformation")
    deny_policy = {
        "Statement": [
            {"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"},
            {
                "Effect": "Deny",
                "Action": "Update:*",
                "Principal": "*",
                "Resource": "LogicalResourceId/Table",
            },
        ]
    }
    cfn.set_stack_policy(StackName=stack_name, StackPolicyBody=json.dumps(deny_policy))

    # Attempt an update while the table is stack-policy-protected.
    cfn.update_stack(StackName=stack_name, TemplateBody=_template(10))
    blocked_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s
        in {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "UPDATE_FAILED"},
        timeout_s=180,
        interval_s=5.0,
        description=f"CFN stack update (protected) {stack_name}",
    )
    assert blocked_status == "UPDATE_ROLLBACK_COMPLETE", (
        f"expected the stack-policy-protected update to roll back, got {blocked_status}"
    )

    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    reasons = " | ".join(e.get("ResourceStatusReason", "") for e in events)
    assert "stack policy" in reasons.lower(), (
        f"expected a stack-policy denial reason among the stack events, got: {reasons!r}"
    )

    # (b) effect absent: the live table's throughput never changed.
    still_protected = dynamodb.describe_table(TableName=table_name)["Table"]
    still_rcu = still_protected["ProvisionedThroughput"]["ReadCapacityUnits"]
    assert still_rcu == 5, f"protected table's ReadCapacityUnits must stay 5, got {still_rcu}"

    # --- Positive control: remove the restriction, then the identical update succeeds. ---
    permissive_policy = {
        "Statement": [{"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"}]
    }
    cfn.set_stack_policy(StackName=stack_name, StackPolicyBody=json.dumps(permissive_policy))
    cfn.update_stack(StackName=stack_name, TemplateBody=_template(10))
    allowed_status = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_FAILED"},
        timeout_s=180,
        interval_s=5.0,
        description=f"CFN stack update (unprotected) {stack_name}",
    )
    assert allowed_status == "UPDATE_COMPLETE", (
        f"expected the identical update to succeed once the stack policy is permissive, got {allowed_status}"
    )
    after = dynamodb.describe_table(TableName=table_name)["Table"]
    after_rcu = after["ProvisionedThroughput"]["ReadCapacityUnits"]
    assert after_rcu == 10, f"unblocked table's ReadCapacityUnits should reach 10, got {after_rcu}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
