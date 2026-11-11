"""cfn-cli-delete-stack-removes-dynamodb-table-positive."""
from __future__ import annotations

import json
import subprocess
import time

from behavioral_harness import tags
from fidelity_tests_runner import require_tools
from botocore.exceptions import ClientError

CHECK = "cfn-cli-delete-stack-removes-dynamodb-table-positive"
GROUP = "resource-lifecycle"
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


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A DynamoDB table with no DeletionPolicy defaults to Delete: once `aws cloudformation delete-stack`
    reaches DELETE_COMPLETE, DescribeTable and PutItem on the table fail with ResourceNotFoundException
    and the exact not-found messages."""
    require_tools("aws")

    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    stack_name = ctx.unique_name("sim2real-cfnddbdel-")

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    # Safety net: if an assertion below fails before the CLI delete-stack runs, this still
    # tears the stack (and its table) down. Idempotent — no-ops once the CLI has already deleted it.
    ctx.on_cleanup(lambda: _delete_stack_and_wait_ignoring_errors(cfn, stack_name))
    status = _wait_stack_status(ctx, cfn, stack_name, {"CREATE_COMPLETE"}, timeout_s=180.0)
    assert status == "CREATE_COMPLETE"

    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    table_name = next(r for r in resources if r["LogicalResourceId"] == "Table")["PhysicalResourceId"]
    # Sanity: the table really exists before we tear it down.
    assert ddb.describe_table(TableName=table_name)["Table"]["TableStatus"] == "ACTIVE"

    _run_aws(ctx, "cloudformation", "delete-stack", "--stack-name", stack_name, timeout_s=60.0)
    del_status = _wait_stack_status(ctx, cfn, stack_name, {"DELETE_COMPLETE"}, timeout_s=180.0)
    assert del_status == "DELETE_COMPLETE"

    code, message = _error(lambda: ddb.describe_table(TableName=table_name))
    assert code == "ResourceNotFoundException", f"table {table_name} still describable after stack delete: {code!r}"
    assert message == f"Requested resource not found: Table: {table_name} not found", (
        f"DescribeTable on deleted table {table_name}: unexpected message {message!r}"
    )

    # Gone means unusable, not just unreadable: a mutation against the dead table must be
    # rejected the same way, not silently accepted by some other physical resource.
    put_code, put_message = _error(
        lambda: ddb.put_item(TableName=table_name, Item={"pk": {"S": "post-delete"}})
    )
    assert put_code == "ResourceNotFoundException", (
        f"PutItem on deleted table {table_name} did not raise ResourceNotFoundException: {put_code!r}"
    )
    assert put_message == "Requested resource not found", (
        f"PutItem on deleted table {table_name}: unexpected message {put_message!r}"
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


def _error(fn):
    """The (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError("the call was expected to be rejected but it succeeded")


def _delete_stack_and_wait_ignoring_errors(cfn, stack_name: str) -> None:
    """Teardown safety net: idempotent no-op if the CLI delete-stack in the check body
    already tore this down. Swallows errors — on_cleanup failures must never mask the
    check's own verdict."""
    try:
        cfn.delete_stack(StackName=stack_name)
        deadline = time.monotonic() + 120.0
        while time.monotonic() < deadline:
            try:
                status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
            except ClientError as exc:
                if exc.response["Error"]["Code"] not in (
                    "StackNotFoundException",
                    "ValidationError",
                ):
                    raise
                return
            if status == "DELETE_COMPLETE":
                return
            time.sleep(5.0)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError"):
            raise


def _wait_stack_status(ctx, cfn, stack_name, target_statuses, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
        except ClientError:
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
