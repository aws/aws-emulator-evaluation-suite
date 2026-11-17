"""delete-item-condition-or-and-precedence-applies-the-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-item-condition-or-and-precedence-applies-the-delete"
GROUP = "conditions"
SERVICES = ["dynamodb"]
_CCFE = ("ConditionalCheckFailedException", "The conditional request failed")


def expect_error(fn, code: str, message: str) -> None:
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DeleteItem's ConditionExpression `A OR B AND C` parses as `A OR (B AND C)` -- AND binds
    tighter than OR -- so a true A alone lets the delete apply even while B AND C is false.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    vals = {":five": {"N": "5"}, ":ten": {"N": "10"}, ":twenty": {"N": "20"}}

    # A=(a=5) true, B=(a=10) false, C=(b=20) false: the explicit grouping `(A OR B) AND C`
    # = (true OR false) AND false = false -- must be refused.
    grouped_key = {"pk": {"S": "di-precedence-grouped"}}
    ddb.put_item(TableName=table, Item={**grouped_key, "a": {"N": "5"}, "b": {"N": "10"}})
    expect_error(
        lambda: ddb.delete_item(
            TableName=table, Key=grouped_key,
            ConditionExpression="(a = :five OR a = :ten) AND b = :twenty",
            ExpressionAttributeValues=vals,
        ),
        *_CCFE,
    )
    still_there = ddb.get_item(TableName=table, Key=grouped_key, ConsistentRead=True).get("Item")
    assert still_there is not None and still_there.get("a") == {"N": "5"}, (
        f"rejected delete under the grouped condition must not remove the item, got {still_there!r}"
    )

    # The identical values under the implicit, unparenthesized `A OR B AND C`: AND binds tighter
    # than OR, so this parses as `A OR (B AND C)` = true OR false = true -- the delete applies.
    implicit_key = {"pk": {"S": "di-precedence-implicit"}}
    ddb.put_item(TableName=table, Item={**implicit_key, "a": {"N": "5"}, "b": {"N": "10"}})
    ddb.delete_item(
        TableName=table, Key=implicit_key,
        ConditionExpression="a = :five OR a = :ten AND b = :twenty",
        ExpressionAttributeValues=vals,
    )
    gone = ddb.get_item(TableName=table, Key=implicit_key, ConsistentRead=True).get("Item")
    assert gone is None, (
        f"expected item absent after the implicit `A OR B AND C` delete applied, got {gone!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
