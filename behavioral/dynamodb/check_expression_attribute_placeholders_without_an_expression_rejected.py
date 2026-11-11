"""expression-attribute-placeholders-without-an-expression-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "expression-attribute-placeholders-without-an-expression-rejected"
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


_NO_EXPR = "ExpressionAttributeValues can only be specified when using expressions"
_NO_EXPR_1 = "1 validation error detected: " + _NO_EXPR
_EAN_NO_EXPR = "ExpressionAttributeNames can only be specified when using expressions"
_EAN_NO_EXPR_1 = "1 validation error detected: " + _EAN_NO_EXPR
_EMPTY_EAV = "ExpressionAttributeValues must not be empty"
_EMPTY_EAV_1 = "1 validation error detected: " + _EMPTY_EAV
_EMPTY_EAN = "ExpressionAttributeNames must not be empty"
_EMPTY_EAN_1 = "1 validation error detected: " + _EMPTY_EAN


def _assert_rejected(call, expected_message, what):
    code, message = _error(call)
    assert code == "ValidationException", (
        f"{what} answered {code!r} ({message!r}), expected ValidationException"
    )
    assert message == expected_message, f"{what}: expected message {expected_message!r}, got {message!r}"


@tags(
    "axis:rejection",
    "concern:negative-classes",
    "concern:representation",
    "dp:api",
    "plane:data",
    "cap:c1",
)
def run(ctx) -> None:
    """ExpressionAttributeValues or ExpressionAttributeNames with no expression to bind into,
    and an empty {} map of either alongside an expression that does use placeholders, is a
    ValidationException on PutItem, DeleteItem, GetItem and Scan, and leaves the table unchanged.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ExpressionAttributeValues.html
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)
    key = {"pk": {"S": "item-1"}}
    ddb.put_item(TableName=table, Item={**key, "color": {"S": "red"}})

    # ExpressionAttributeValues/Names with no expression present.
    _assert_rejected(
        lambda: ddb.put_item(
            TableName=table, Item={"pk": {"S": "new-eav"}},
            ExpressionAttributeValues={":v": {"S": "x"}},
        ),
        _NO_EXPR_1, "PutItem with EAV and no expression",
    )
    _assert_rejected(
        lambda: ddb.put_item(
            TableName=table, Item={"pk": {"S": "new-ean"}},
            ExpressionAttributeNames={"#n": "n"},
        ),
        _EAN_NO_EXPR_1, "PutItem with EAN and no expression",
    )
    _assert_rejected(
        lambda: ddb.delete_item(
            TableName=table, Key=key, ExpressionAttributeValues={":v": {"S": "x"}},
        ),
        _NO_EXPR_1, "DeleteItem with EAV and no expression",
    )
    _assert_rejected(
        lambda: ddb.delete_item(
            TableName=table, Key=key, ExpressionAttributeNames={"#n": "n"},
        ),
        _EAN_NO_EXPR_1, "DeleteItem with EAN and no expression",
    )
    _assert_rejected(
        lambda: ddb.get_item(
            TableName=table, Key=key, ExpressionAttributeNames={"#n": "n"},
        ),
        _EAN_NO_EXPR, "GetItem with EAN and no expression",
    )
    _assert_rejected(
        lambda: ddb.scan(
            TableName=table, ExpressionAttributeValues={":v": {"S": "x"}},
        ),
        _NO_EXPR, "Scan with EAV and no expression",
    )
    _assert_rejected(
        lambda: ddb.scan(
            TableName=table, ExpressionAttributeNames={"#n": "n"},
        ),
        _EAN_NO_EXPR, "Scan with EAN and no expression",
    )

    # An empty {} map alongside a valid expression that does use placeholders.
    _assert_rejected(
        lambda: ddb.put_item(
            TableName=table, Item={"pk": {"S": "new-emptyeav"}},
            ConditionExpression="attribute_not_exists(pk)", ExpressionAttributeValues={},
        ),
        _EMPTY_EAV_1, "PutItem with an empty EAV map and a valid ConditionExpression",
    )
    _assert_rejected(
        lambda: ddb.put_item(
            TableName=table, Item={"pk": {"S": "new-emptyean"}},
            ConditionExpression="attribute_not_exists(pk)", ExpressionAttributeNames={},
        ),
        _EMPTY_EAN_1, "PutItem with an empty EAN map and a valid ConditionExpression",
    )
    _assert_rejected(
        lambda: ddb.delete_item(
            TableName=table, Key=key,
            ConditionExpression="attribute_exists(pk)", ExpressionAttributeValues={},
        ),
        _EMPTY_EAV_1, "DeleteItem with an empty EAV map and a valid ConditionExpression",
    )
    _assert_rejected(
        lambda: ddb.get_item(
            TableName=table, Key=key,
            ProjectionExpression="pk", ExpressionAttributeNames={},
        ),
        _EMPTY_EAN, "GetItem with an empty EAN map and a valid ProjectionExpression",
    )
    _assert_rejected(
        lambda: ddb.scan(
            TableName=table,
            FilterExpression="attribute_exists(pk)", ExpressionAttributeValues={},
        ),
        _EMPTY_EAV, "Scan with an empty EAV map and a valid FilterExpression",
    )
    _assert_rejected(
        lambda: ddb.scan(
            TableName=table,
            FilterExpression="attribute_exists(pk)", ExpressionAttributeNames={},
        ),
        _EMPTY_EAN, "Scan with an empty EAN map and a valid FilterExpression",
    )

    # None of the twelve refused calls wrote anything: the table holds exactly the one item.
    items = ddb.scan(TableName=table, ConsistentRead=True)["Items"]
    assert items == [{**key, "color": {"S": "red"}}], (
        f"table holds {items!r} after every refusal above; expected only the original item"
    )

    # Positive control: the same shapes, used correctly, succeed.
    ddb.put_item(
        TableName=table, Item={"pk": {"S": "new-ok"}},
        ConditionExpression="attribute_not_exists(#p)",
        ExpressionAttributeNames={"#p": "pk"},
    )
    got = ddb.get_item(TableName=table, Key={"pk": {"S": "new-ok"}}, ConsistentRead=True)["Item"]
    assert got == {"pk": {"S": "new-ok"}}, f"positive-control PutItem left {got!r}"
    ddb.delete_item(TableName=table, Key={"pk": {"S": "new-ok"}})


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
