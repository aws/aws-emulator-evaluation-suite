"""deploy-dynamodb-table-put-get-item."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-dynamodb-table-put-get-item"
GROUP = "deploy"
SERVICES = ["cloudformation"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A DynamoDB table deployed via CloudFormation accepts a PutItem and returns it
    unchanged on GetItem -- proving the resource is functional, not just registered."""
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")
    stack_name = ctx.unique_name("sim2real-behav-ddb-")

    template = """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Table:
    Type: AWS::DynamoDB::Table
    Properties:
      BillingMode: PAY_PER_REQUEST
      AttributeDefinitions:
        - AttributeName: pk
          AttributeType: S
      KeySchema:
        - AttributeName: pk
          KeyType: HASH
Outputs:
  TableName:
    Value: !Ref Table
"""

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Tags=[{"Key": "sim2real", "Value": "deploy-dynamodb-table-put-get-item"}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))

    status = _wait_stack_terminal(ctx, stack_name, timeout_s=180)
    assert status == "CREATE_COMPLETE", f"stack did not reach CREATE_COMPLETE (got {status})"

    resources = cfn.describe_stack_resources(StackName=stack_name)["StackResources"]
    table_resource = next(r for r in resources if r["LogicalResourceId"] == "Table")
    table_name = table_resource["PhysicalResourceId"]

    ddb.put_item(
        TableName=table_name,
        Item={"pk": {"S": "item-1"}, "value": {"S": "hello-world"}, "count": {"N": "42"}},
    )
    got = ddb.get_item(TableName=table_name, Key={"pk": {"S": "item-1"}}, ConsistentRead=True)["Item"]
    assert got["pk"]["S"] == "item-1", f"expected pk=item-1, got {got.get('pk')}"
    assert got["value"]["S"] == "hello-world", f"expected value=hello-world, got {got.get('value')}"
    assert got["count"]["N"] == "42", f"expected count=42, got {got.get('count')}"

    # The stack is torn down here (not left to on_cleanup alone) so the
    # teardown itself can be asserted -- an independent read at the destination, not
    # CFN's own DELETE_COMPLETE echo.
    cfn.delete_stack(StackName=stack_name)
    delete_status = _wait_stack_terminal(ctx, stack_name, timeout_s=180)
    assert delete_status == "DELETE_COMPLETE", (
        f"expected DELETE_COMPLETE tearing down {stack_name}, got {delete_status}"
    )

    describe_got = _expect_error(lambda: ddb.describe_table(TableName=table_name))
    describe_expected = (
        "ResourceNotFoundException", f"Requested resource not found: Table: {table_name} not found"
    )
    assert describe_got == describe_expected, (
        f"DescribeTable on the deleted table: expected {describe_expected!r}, got {describe_got!r}"
    )
    get_got = _expect_error(lambda: ddb.get_item(TableName=table_name, Key={"pk": {"S": "item-1"}}))
    get_expected = ("ResourceNotFoundException", "Requested resource not found")
    assert get_got == get_expected, (
        f"GetItem on the deleted table: expected {get_expected!r}, got {get_got!r}"
    )


_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "UPDATE_COMPLETE",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE",
    "DELETE_FAILED",
    "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
}


def _wait_stack_terminal(ctx, stack_name: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> str:
    cfn = ctx.client("cloudformation")
    status = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError":
                # the stack has aged out of DescribeStacks entirely -- only reachable
                # post-delete, so this IS the terminal state, not a transient gap.
                return "DELETE_COMPLETE"
            raise
        if status in _TERMINAL_STACK_STATUSES:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} did not reach a terminal status within {timeout_s}s (last={status})")


def _expect_error(fn):
    """Call fn(); return the ClientError (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
