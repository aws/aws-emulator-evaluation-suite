"""projection-negative-list-index-rejected-across-read-operations."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "projection-negative-list-index-rejected-across-read-operations"
GROUP = "item_crud"
SERVICES = ["dynamodb"]

_INVALID = ("ValidationException", 'Invalid ProjectionExpression: Syntax error; token: "-", near: "[-1"')


def _error(fn):
    """The (code, message) ``fn`` raises. An unexpected success raises too, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got = _error(fn)
    assert got == (code, message), f"got {got!r}, expected {(code, message)!r}"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ProjectionExpression list index written as a negative integer is refused with the same
    syntax-error message on GetItem, Query, Scan and BatchGetItem, and GetItem with a non-negative
    index returns that element.
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "row"}, "sk": {"S": "only"}}

    ddb.put_item(
        TableName=table,
        Item={"pk": {"S": "row"}, "sk": {"S": "only"}, "l": {"L": [{"S": "zero"}, {"S": "one"}]}},
    )

    def _call(op: str, expr: str):
        if op == "GetItem":
            return ddb.get_item(
                TableName=table, Key=key, ConsistentRead=True,
                ProjectionExpression=expr, ExpressionAttributeNames={"#l": "l"},
            )
        if op == "Query":
            return ddb.query(
                TableName=table,
                KeyConditionExpression="#pk = :pk",
                ExpressionAttributeNames={"#pk": "pk", "#l": "l"},
                ExpressionAttributeValues={":pk": {"S": "row"}},
                ProjectionExpression=expr, ConsistentRead=True,
            )
        if op == "Scan":
            return ddb.scan(
                TableName=table, ProjectionExpression=expr,
                ExpressionAttributeNames={"#l": "l"}, ConsistentRead=True,
            )
        return ddb.batch_get_item(RequestItems={table: {
            "Keys": [key], "ProjectionExpression": expr,
            "ExpressionAttributeNames": {"#l": "l"}, "ConsistentRead": True,
        }})

    # --- every read op refuses a negative list index with the identical syntax-error message ---
    for op in ("GetItem", "Query", "Scan", "BatchGetItem"):
        expect_error(lambda op=op: _call(op, "#l[-1]"), *_INVALID)

    # --- positive control: GetItem with a non-negative index returns that element ---
    got = ddb.get_item(
        TableName=table, Key=key, ConsistentRead=True,
        ProjectionExpression="#l[1]", ExpressionAttributeNames={"#l": "l"},
    )["Item"]
    assert got == {"l": {"L": [{"S": "one"}]}}, (
        f"GetItem '#l[1]' must succeed and return the element at index 1; got {got!r}"
    )


def _create_table(ctx, ddb) -> str:
    name = ctx.unique_name("sim2real-behav-projnegidx-")
    ddb.create_table(
        TableName=name,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
        ],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    _wait_table_active(ddb, name)
    return name


def _wait_table_active(ddb, name: str, timeout_s: float = 60.0, interval_s: float = 2.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        time.sleep(interval_s)
    raise AssertionError(f"table {name} never became ACTIVE")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
