"""empty-string-expression-rejected-across-operations."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "empty-string-expression-rejected-across-operations"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_TABLE_ACTIVE_BUDGET_S = 120.0
_TEARDOWN_WAIT_S = 120.0


def _error(fn):
    """(code, message) of the ClientError fn() raises; RAISES if the call unexpectedly succeeds."""
    try:
        resp = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"call unexpectedly SUCCEEDED where an error was required: {resp!r}")


def _delete_table_when_possible(ddb, table_name):
    deadline = time.monotonic() + _TEARDOWN_WAIT_S
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code == "ResourceInUseException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise


def _create_table(ctx, ddb):
    name = ctx.unique_name("sim2real-behav-ddb-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_when_possible(ddb, name))
    deadline = time.monotonic() + _TABLE_ACTIVE_BUDGET_S
    status = None
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return name
        time.sleep(2.0)
    raise AssertionError(f"table {name!r} not ACTIVE within {_TABLE_ACTIVE_BUDGET_S}s: {status!r}")


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """An empty-string ConditionExpression, UpdateExpression, KeyConditionExpression,
    FilterExpression or ProjectionExpression is a ValidationException on every operation that
    accepts it, and a refused PutItem, DeleteItem or UpdateItem leaves the item unchanged.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.html
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "item-1"}}
    ddb.put_item(TableName=table, Item={**key, "color": {"S": "red"}})

    # 1. PutItem with an empty ConditionExpression.
    code, message = _error(lambda: ddb.put_item(
        TableName=table, Item={**key, "color": {"S": "blue"}}, ConditionExpression="",
    ))
    assert code == "ValidationException", (
        f"PutItem with ConditionExpression='' answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    expected = "1 validation error detected: Invalid ConditionExpression: The expression can not be empty;"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert item == {**key, "color": {"S": "red"}}, (
        f"after the refused PutItem the item is {item!r}; expected color still 'red'"
    )

    # 2. DeleteItem with an empty ConditionExpression.
    code, message = _error(lambda: ddb.delete_item(
        TableName=table, Key=key, ConditionExpression="",
    ))
    assert code == "ValidationException", (
        f"DeleteItem with ConditionExpression='' answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    expected = "1 validation error detected: Invalid ConditionExpression: The expression can not be empty;"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert item == {**key, "color": {"S": "red"}}, (
        f"after the refused DeleteItem the item is {item!r}; expected it still present and unchanged"
    )

    # 3. UpdateItem with an empty UpdateExpression.
    code, message = _error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="",
    ))
    assert code == "ValidationException", (
        f"UpdateItem with UpdateExpression='' answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    expected = "1 validation error detected: Invalid UpdateExpression: The expression can not be empty;"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    item = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert item == {**key, "color": {"S": "red"}}, (
        f"after the refused UpdateItem the item is {item!r}; expected color still 'red'"
    )

    # 4. Query with an empty KeyConditionExpression.
    code, message = _error(lambda: ddb.query(
        TableName=table, KeyConditionExpression="",
    ))
    assert code == "ValidationException", (
        f"Query with KeyConditionExpression='' answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    expected = "Invalid KeyConditionExpression: The expression can not be empty;"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # 5. Scan with an empty FilterExpression.
    code, message = _error(lambda: ddb.scan(
        TableName=table, FilterExpression="",
    ))
    assert code == "ValidationException", (
        f"Scan with FilterExpression='' answered {code!r} ({message!r}), expected ValidationException"
    )
    expected = "Invalid FilterExpression: The expression can not be empty;"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # 6. GetItem with an empty ProjectionExpression.
    code, message = _error(lambda: ddb.get_item(
        TableName=table, Key=key, ProjectionExpression="",
    ))
    assert code == "ValidationException", (
        f"GetItem with ProjectionExpression='' answered {code!r} ({message!r}), expected "
        f"ValidationException"
    )
    expected = "Invalid ProjectionExpression: The expression can not be empty;"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the same five shapes, with a real expression, all succeed.
    ddb.put_item(
        TableName=table, Item={**key, "color": {"S": "green"}},
        ConditionExpression="attribute_exists(pk)",
    )
    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="SET #c = :v",
        ExpressionAttributeNames={"#c": "color"}, ExpressionAttributeValues={":v": {"S": "yellow"}},
    )
    rows = ddb.query(
        TableName=table, KeyConditionExpression="pk = :p", ExpressionAttributeValues={":p": {"S": "item-1"}},
    )["Items"]
    assert rows == [{**key, "color": {"S": "yellow"}}], (
        f"the positive-control Query returned {rows!r}, expected the item colored yellow"
    )
    rows = ddb.scan(TableName=table, FilterExpression="attribute_exists(pk)")["Items"]
    assert rows == [{**key, "color": {"S": "yellow"}}], (
        f"the positive-control Scan returned {rows!r}, expected the item colored yellow"
    )
    projected = ddb.get_item(TableName=table, Key=key, ProjectionExpression="pk")["Item"]
    assert projected == key, f"the positive-control GetItem projection returned {projected!r}, expected only pk"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
