"""update-item-condition-string-lexicographic-comparison."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-item-condition-string-lexicographic-comparison"
GROUP = "conditions"
SERVICES = ["dynamodb"]
_CCF = ("ConditionalCheckFailedException", "The conditional request failed")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    """Assert fn() raises exactly (code, message)."""
    got = _error(fn)
    assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An UpdateItem ConditionExpression comparing String attributes orders them
    lexicographically (a shorter prefix is less than its extension) and treats two equal
    strings as not less-than, rejecting the write with ConditionalCheckFailedException.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-strcmp-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "strcmp"}}
    ddb.put_item(TableName=table, Item={**key, "label": {"S": "apple"}})

    def read():
        return ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]

    def update(new_val, threshold):
        ddb.update_item(
            TableName=table,
            Key=key,
            UpdateExpression="SET val = :v",
            ConditionExpression="label < :threshold",
            ExpressionAttributeValues={":v": {"S": new_val}, ":threshold": {"S": threshold}},
        )

    # Positive control: "apple" is a strict prefix of "applesauce", so it is lexicographically
    # less than it even though the shared prefix compares equal character by character.
    update("admitted", "applesauce")
    got = read()
    assert got["val"] == {"S": "admitted"}, (
        f"'apple' < 'applesauce' should admit the update, got val={got.get('val')!r}"
    )

    # Negative: two equal strings are never less-than each other, so the write is refused and
    # the item is left exactly as the positive control left it.
    expect_error(lambda: update("rejected", "apple"), *_CCF)
    unchanged = read()
    assert unchanged["val"] == {"S": "admitted"}, (
        f"rejected update via 'apple' < 'apple' must leave val unchanged, got {unchanged.get('val')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
