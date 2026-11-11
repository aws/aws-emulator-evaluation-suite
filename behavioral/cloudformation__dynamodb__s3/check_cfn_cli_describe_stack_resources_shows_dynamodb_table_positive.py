"""cfn-cli-describe-stack-resources-shows-dynamodb-table-positive."""
from __future__ import annotations

import json
import subprocess
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "cfn-cli-describe-stack-resources-shows-dynamodb-table-positive"
GROUP = "resource-binding"
SERVICES = ["cloudformation", "dynamodb", "s3"]

_TEMPLATE = json.dumps(
    {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Table": {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "BillingMode": "PAY_PER_REQUEST",
                    "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                },
            }
        },
    }
)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """`aws cloudformation describe-stack-resources` reports a PhysicalResourceId for the
    DynamoDB table logical resource that matches a real, ACTIVE table independently
    confirmed via dynamodb.describe_table — not a synthetic or stale identifier."""
    require_tools("aws")

    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    stack_name = ctx.unique_name("sim2real-cfnddb-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )

    def _cleanup():
        cfn.delete_stack(StackName=stack_name)
        _wait_stack_status(ctx, cfn, stack_name, {"DELETE_COMPLETE"}, timeout_s=180.0)

    ctx.on_cleanup(_cleanup)

    status = _wait_stack_status(ctx, cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=180.0)
    assert status == "CREATE_COMPLETE", f"expected stack {stack_name} to reach CREATE_COMPLETE, got {status}"

    resources = _run_aws(ctx, "cloudformation", "describe-stack-resources", "--stack-name", stack_name)
    table_resource = next(
        r for r in resources["StackResources"] if r["LogicalResourceId"] == "Table"
    )
    assert table_resource["ResourceType"] == "AWS::DynamoDB::Table", (
        f"expected logical resource 'Table' to be AWS::DynamoDB::Table, got {table_resource['ResourceType']!r}"
    )
    physical_table_name = table_resource["PhysicalResourceId"]

    described = ddb.describe_table(TableName=physical_table_name)["Table"]
    assert described["TableName"] == physical_table_name, (
        f"dynamodb.describe_table reports TableName {described['TableName']!r}, "
        f"expected it to match the CLI-reported PhysicalResourceId {physical_table_name!r}"
    )
    assert described["TableStatus"] == "ACTIVE", (
        f"expected the table bound by describe-stack-resources to be ACTIVE, got {described['TableStatus']!r}"
    )


def _run_shell(ctx, command, *, env_extra=None, timeout_s=60.0, check=True, cwd=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    if env_extra:
        env.update(env_extra)
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=cwd,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


def _run_aws(ctx, *args: str, timeout_s=30.0, check=True):
    proc = _run_shell(
        ctx,
        ["aws", "--output", "json", *args],
        timeout_s=timeout_s,
        check=check,
    )
    if not proc.stdout.strip():
        return {}
    try:
        return json.loads(proc.stdout)
    except (json.JSONDecodeError, ValueError):
        return proc.stdout.strip()


def _wait_stack_status(ctx, cfn, stack_name, target_statuses, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
        except Exception:
            if "DELETE_COMPLETE" in target_statuses:
                return "DELETE_COMPLETE"
            raise
        last = resp["Stacks"][0]["StackStatus"]
        if last in target_statuses:
            return last
        if last.endswith("FAILED"):
            raise AssertionError(f"stack {stack_name} entered unexpected status {last}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach {target_statuses} within {timeout_s}s (last={last})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
