"""delete-item-condition-contains-list-of-maps-partial-operand-false."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-item-condition-contains-list-of-maps-partial-operand-false"
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
    """DeleteItem's ConditionExpression contains() over a list of maps needs full element
    equality: a map operand that is a strict subset of one list element's keys does not satisfy
    contains, so the delete is refused.
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

    element_0 = {"M": {"a": {"S": "1"}, "b": {"S": "2"}}}
    element_1 = {"M": {"a": {"S": "9"}, "b": {"S": "9"}}}
    list_attr = {"L": [element_0, element_1]}
    partial_map = {"M": {"a": {"S": "1"}}}
    full_match_map = {"M": {"b": {"S": "2"}, "a": {"S": "1"}}}

    key = {"pk": {"S": "di-contains-partial"}}
    ddb.put_item(TableName=table, Item={**key, "entries": list_attr})

    # Break: the operand carries only a subset of element_0's keys, so no list element equals
    # it exactly -- contains() must be false, not "true because it matches a prefix of keys".
    expect_error(
        lambda: ddb.delete_item(
            TableName=table, Key=key,
            ConditionExpression="contains(entries, :partial)",
            ExpressionAttributeValues={":partial": partial_map},
        ),
        *_CCFE,
    )

    # Effect absent: the rejected delete must not have removed the item.
    still_there = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert still_there is not None and still_there.get("entries") == list_attr, (
        f"rejected delete must not remove the item, got {still_there!r}"
    )

    # Positive control: the identical shape, but the operand is key-for-key and value-for-value
    # equal to element_0 (key order in the request differs) -- contains() is true and the delete
    # applies, proving the refusal above was the partial match and not the function itself.
    ddb.delete_item(
        TableName=table, Key=key,
        ConditionExpression="contains(entries, :match)",
        ExpressionAttributeValues={":match": full_match_map},
    )
    gone = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item")
    assert gone is None, f"expected item absent after the satisfied contains() delete, got {gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
