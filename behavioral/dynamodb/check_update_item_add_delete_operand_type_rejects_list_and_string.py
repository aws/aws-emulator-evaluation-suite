"""update-item-add-delete-operand-type-rejects-list-and-string."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-add-delete-operand-type-rejects-list-and-string"
GROUP = "negative-classes"
SERVICES = ["dynamodb"]

_ADD_LIST = (
    "ValidationException",
    "1 validation error detected: Invalid UpdateExpression: Incorrect operand type for "
    "operator or function; operator: ADD, operand type: LIST, typeSet: ALLOWED_FOR_ADD_OPERAND",
)
_DELETE_STRING = (
    "ValidationException",
    "1 validation error detected: Invalid UpdateExpression: Incorrect operand type for "
    "operator or function; operator: DELETE, operand type: STRING, typeSet: ALLOWED_FOR_ADD_OPERAND",
)


def expect_error(fn, code: str, message: str) -> None:
    """Assert `fn()` raises a ClientError with exactly `(code, message)`; raises on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err["Code"], err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem's ADD rejects a List operand and DELETE rejects a String operand with the
    operator's typeSet error, on a fresh attribute and on one that already holds another type.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "x"}}
    ddb.put_item(TableName=table, Item={**key, "count": {"N": "5"}, "tags": {"SS": ["a", "b"]}})

    # 1. ADD with a List operand onto an attribute that does not exist yet.
    expect_error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD freshList :v",
        ExpressionAttributeValues={":v": {"L": [{"S": "z"}]}},
    ), *_ADD_LIST)
    after1 = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert "freshList" not in after1, f"the rejected ADD must not create the attribute, got {after1!r}"

    # 2. DELETE with a String operand onto an attribute that does not exist yet.
    expect_error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE freshStr :v",
        ExpressionAttributeValues={":v": {"S": "z"}},
    ), *_DELETE_STRING)
    after2 = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert "freshStr" not in after2, f"the rejected DELETE must not create the attribute, got {after2!r}"

    # 3. ADD with a List operand onto an attribute that already holds a Number.
    expect_error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD #c :v",
        ExpressionAttributeNames={"#c": "count"}, ExpressionAttributeValues={":v": {"L": [{"S": "z"}]}},
    ), *_ADD_LIST)
    after3 = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert after3["count"] == {"N": "5"}, f"the rejected ADD must leave count unchanged, got {after3['count']!r}"

    # 4. DELETE with a String operand onto an attribute that already holds a String Set.
    expect_error(lambda: ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE #t :v",
        ExpressionAttributeNames={"#t": "tags"}, ExpressionAttributeValues={":v": {"S": "z"}},
    ), *_DELETE_STRING)
    after4 = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert set(after4["tags"]["SS"]) == {"a", "b"}, (
        f"the rejected DELETE must leave tags unchanged, got {after4['tags']!r}"
    )

    # Positive controls: same-typed operands still apply.
    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD #c :v",
        ExpressionAttributeNames={"#c": "count"}, ExpressionAttributeValues={":v": {"N": "3"}},
    )
    grown = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert grown["count"] == {"N": "8"}, f"the positive-control ADD must apply, got {grown['count']!r}"

    ddb.update_item(
        TableName=table, Key=key, UpdateExpression="DELETE #t :v",
        ExpressionAttributeNames={"#t": "tags"}, ExpressionAttributeValues={":v": {"SS": ["a"]}},
    )
    shrunk = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert set(shrunk["tags"]["SS"]) == {"b"}, f"the positive-control DELETE must apply, got {shrunk['tags']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
