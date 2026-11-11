"""putitem-not-contains-condition-gates-the-write."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "putitem-not-contains-condition-gates-the-write"
GROUP = "expressions"
SERVICES = ["dynamodb"]

_COND_FAILED = ("ConditionalCheckFailedException", "The conditional request failed")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``; an unexpected success fails too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        got = (err.get("Code"), err.get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A PutItem ConditionExpression `NOT contains(#r, :v)` is refused with ConditionalCheckFailedException,
    item unchanged, when `:v` is an SS member by value and type; it succeeds, replacing the item,
    when `:v` is the same digits under a different type, since contains() never matches across types.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.ConditionExpressions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbnc-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "target"}}
    initial = {**key, "roles": {"SS": ["5"]}}
    ddb.put_item(TableName=table, Item=initial)

    names = {"#r": "roles"}

    # The condition is false: contains(roles, S "5") is true (type-matched set membership), so
    # NOT contains(...) fails the write and leaves the item exactly as it was.
    expect_error(
        lambda: ddb.put_item(
            TableName=table, Item={**key, "roles": {"SS": ["5"]}, "written": {"BOOL": True}},
            ConditionExpression="NOT contains(#r, :v)",
            ExpressionAttributeNames=names, ExpressionAttributeValues={":v": {"S": "5"}},
        ),
        *_COND_FAILED,
    )
    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged == initial, f"PutItem under a failing NOT contains() condition left {unchanged!r}, expected {initial!r} unchanged"

    # The condition is true: contains(roles, N "5") is false (the SS holds strings, not
    # numbers, so a cross-type operand never matches), so NOT contains(...) holds and the
    # write replaces the item.
    ddb.put_item(
        TableName=table, Item={**key, "roles": {"SS": ["5"]}, "written": {"BOOL": True}},
        ConditionExpression="NOT contains(#r, :v)",
        ExpressionAttributeNames=names, ExpressionAttributeValues={":v": {"N": "5"}},
    )
    replaced = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    expected = {**key, "roles": {"SS": ["5"]}, "written": {"BOOL": True}}
    assert replaced == expected, f"PutItem under a holding NOT contains() condition left {replaced!r}, expected {expected!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
