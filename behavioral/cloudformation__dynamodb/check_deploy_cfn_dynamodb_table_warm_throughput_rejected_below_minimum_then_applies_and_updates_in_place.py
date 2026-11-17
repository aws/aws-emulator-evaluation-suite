"""deploy-cfn-dynamodb-table-warm-throughput-rejected-below-minimum-then-applies-and-updates-in-place."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-dynamodb-table-warm-throughput-rejected-below-minimum-then-applies-and-updates-in-place"
GROUP = "deploy"
SERVICES = ["cloudformation", "dynamodb"]

_LOGICAL_ID = "Tbl"
_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})
_NOT_FOUND = ("ResourceNotFoundException", "{table} not found")


def _template(table_name: str, *, read_units: int, write_units: int) -> str:
    return json.dumps({
        "Resources": {
            _LOGICAL_ID: {
                "Type": "AWS::DynamoDB::Table",
                "Properties": {
                    "TableName": table_name,
                    "AttributeDefinitions": [{"AttributeName": "id", "AttributeType": "S"}],
                    "KeySchema": [{"AttributeName": "id", "KeyType": "HASH"}],
                    "BillingMode": "PAY_PER_REQUEST",
                    "WarmThroughput": {
                        "ReadUnitsPerSecond": read_units,
                        "WriteUnitsPerSecond": write_units,
                    },
                },
            },
        },
    })


def _wait_stack(cfn, stack_id: str, timeout_s: float = 300.0) -> str:
    """Poll DescribeStacks by id every 2s until a status in _TERMINAL; return it."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL:
            return status
        time.sleep(2)
    raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")


def _delete_stack(cfn, stack_id: str, timeout_s: float = 300.0) -> None:
    """Delete by id and wait for DELETE_COMPLETE; a non-terminal or DELETE_FAILED result raises."""
    try:
        cfn.delete_stack(StackName=stack_id)
    except ClientError as exc:
        if exc.response["Error"].get("Code") == "ValidationError":
            return
        raise
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"].get("Code") == "ValidationError":
                return
            raise
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_id} delete reached DELETE_FAILED")
        time.sleep(2)
    raise AssertionError(f"stack {stack_id} not deleted within {timeout_s:.0f}s (last {status!r})")


def _validation_failures(cfn, stack_name: str) -> list:
    """``(path, reason)`` of every VALIDATION_ERROR DescribeEvents reports for the stack."""
    out: list = []
    kwargs = {"StackName": stack_name}
    while True:
        page = cfn.describe_events(**kwargs)
        out.extend(
            (e.get("ValidationPath"), e.get("ValidationStatusReason"))
            for e in page["OperationEvents"] if e.get("EventType") == "VALIDATION_ERROR"
        )
        token = page.get("NextToken")
        if not token:
            return out
        kwargs["NextToken"] = token


def _error(fn) -> tuple:
    """``(Error.Code, Error.Message)`` of the ClientError ``fn`` raises; a success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A WarmThroughput below its minimum of 1 unit per second fails CFN's property validation
    before any table is provisioned; a valid WarmThroughput deploys, DescribeTable reads back the
    declared values, and raising them through UpdateStack applies in place.
    """
    cfn = ctx.client("cloudformation")
    ddb = ctx.client("dynamodb")

    # --- the rejection: ReadUnitsPerSecond below its minimum of 1 -----------------------------
    bad_table = ctx.unique_name("sim2real-ddbwarm-bad-")
    bad_stack = ctx.unique_name("sim2real-cfn-ddbwarm-bad-")
    cfn.create_stack(StackName=bad_stack,
                      TemplateBody=_template(bad_table, read_units=0, write_units=10),
                      Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_stack(cfn, bad_stack))

    bad_status = _wait_stack(cfn, bad_stack)
    assert bad_status == "ROLLBACK_COMPLETE", (
        f"a WarmThroughput below its minimum must roll the stack back; ended at {bad_status!r}"
    )
    failures = _validation_failures(cfn, bad_stack)
    want_path = f"/Resources/{_LOGICAL_ID}/Properties/WarmThroughput/ReadUnitsPerSecond"
    want_reason = "#/WarmThroughput/ReadUnitsPerSecond: 0 is not greater or equal to 1"
    assert failures == [(want_path, want_reason)], (
        f"expected one validation failure {(want_path, want_reason)!r}, got {failures!r}"
    )
    resources = cfn.list_stack_resources(StackName=bad_stack)["StackResourceSummaries"]
    assert resources == [], f"a stack refused before provisioning must own no resource, got {resources!r}"

    code, message = _error(lambda: ddb.describe_table(TableName=bad_table))
    assert code == _NOT_FOUND[0] and message == f"Requested resource not found: Table: {bad_table} not found", (
        f"the never-provisioned table's DescribeTable answered ({code!r}, {message!r})"
    )

    # --- the positive control: a valid WarmThroughput deploys, reads back, updates in place --
    good_table = ctx.unique_name("sim2real-ddbwarm-good-")
    good_stack = ctx.unique_name("sim2real-cfn-ddbwarm-good-")
    cfn.create_stack(StackName=good_stack,
                      TemplateBody=_template(good_table, read_units=15000, write_units=15000),
                      Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_stack(cfn, good_stack))

    good_status = _wait_stack(cfn, good_stack)
    assert good_status == "CREATE_COMPLETE", f"the valid template must deploy; ended at {good_status!r}"
    physical = cfn.describe_stack_resource(
        StackName=good_stack, LogicalResourceId=_LOGICAL_ID)["StackResourceDetail"]["PhysicalResourceId"]
    assert physical == good_table, f"the table's physical id must be its declared name, got {physical!r}"

    warm = _poll_warm_throughput(ddb, good_table)
    assert warm == {"ReadUnitsPerSecond": 15000, "WriteUnitsPerSecond": 15000, "Status": "ACTIVE"}, (
        f"the declared WarmThroughput must read back from DescribeTable, got {warm!r}"
    )

    cfn.update_stack(StackName=good_stack,
                      TemplateBody=_template(good_table, read_units=20000, write_units=20000))
    update_status = _wait_stack(cfn, good_stack)
    assert update_status == "UPDATE_COMPLETE", f"raising WarmThroughput must update in place; ended at {update_status!r}"
    after_physical = cfn.describe_stack_resource(
        StackName=good_stack, LogicalResourceId=_LOGICAL_ID)["StackResourceDetail"]["PhysicalResourceId"]
    assert after_physical == physical, "the physical resource id changed across the update: the table was replaced"

    warm_after = _poll_warm_throughput(ddb, good_table)
    assert warm_after == {"ReadUnitsPerSecond": 20000, "WriteUnitsPerSecond": 20000, "Status": "ACTIVE"}, (
        f"the raised WarmThroughput must read back after the update, got {warm_after!r}"
    )

    _delete_stack(cfn, good_stack)
    code, message = _error(lambda: ddb.describe_table(TableName=good_table))
    assert code == _NOT_FOUND[0] and message == f"Requested resource not found: Table: {good_table} not found", (
        f"after DeleteStack, DescribeTable for {good_table!r} answered ({code!r}, {message!r})"
    )


def _poll_warm_throughput(ddb, table_name: str, timeout_s: float = 600.0) -> dict:
    """DescribeTable's WarmThroughput once its Status leaves any transitional value."""
    deadline = time.monotonic() + timeout_s
    warm = None
    while time.monotonic() < deadline:
        warm = ddb.describe_table(TableName=table_name)["Table"].get("WarmThroughput")
        if warm is not None and warm.get("Status") in ("ACTIVE",):
            return warm
        time.sleep(3)
    raise AssertionError(f"WarmThroughput on {table_name} never settled within {timeout_s:.0f}s: {warm!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
