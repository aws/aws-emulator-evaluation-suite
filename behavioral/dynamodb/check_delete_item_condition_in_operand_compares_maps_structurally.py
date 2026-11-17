"""delete-item-condition-in-operand-compares-maps-structurally."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-item-condition-in-operand-compares-maps-structurally"
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
    """DeleteItem's ConditionExpression IN compares a map operand structurally: the delete applies
    only when the stored map equals one of the IN list's maps member-for-member, not by key subset
    or superset.
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

    stored_map = {"M": {"a": {"S": "1"}, "b": {"S": "2"}}}
    superset_map = {"M": {"a": {"S": "1"}, "b": {"S": "2"}, "c": {"S": "3"}}}
    subset_map = {"M": {"a": {"S": "1"}}}
    other_map = {"M": {"a": {"S": "9"}, "b": {"S": "9"}}}
    matching_map = {"M": {"b": {"S": "2"}, "a": {"S": "1"}}}

    near_miss_key = {"pk": {"S": "di-in-near-miss"}}
    ddb.put_item(TableName=table, Item={**near_miss_key, "m": stored_map})

    # Break: the IN list carries a superset and a subset of the stored map's keys, and an
    # unrelated map, but never the stored map itself -- none compares equal structurally.
    expect_error(
        lambda: ddb.delete_item(
            TableName=table, Key=near_miss_key,
            ConditionExpression="m IN (:sup, :sub, :other)",
            ExpressionAttributeValues={":sup": superset_map, ":sub": subset_map, ":other": other_map},
        ),
        *_CCFE,
    )

    # Effect absent: the rejected delete must not have removed the item.
    still_there = ddb.get_item(TableName=table, Key=near_miss_key, ConsistentRead=True).get("Item")
    assert still_there is not None and still_there.get("m") == stored_map, (
        f"rejected delete must not remove the item, got {still_there!r}"
    )

    # Positive control: the identical shape, but the IN list's last entry is key-for-key and
    # value-for-value equal to the stored map (key order in the request differs) -- it matches
    # structurally and the delete applies.
    ddb.delete_item(
        TableName=table, Key=near_miss_key,
        ConditionExpression="m IN (:sup, :sub, :match)",
        ExpressionAttributeValues={":sup": superset_map, ":sub": subset_map, ":match": matching_map},
    )
    gone = ddb.get_item(TableName=table, Key=near_miss_key, ConsistentRead=True).get("Item")
    assert gone is None, f"expected item absent after the satisfied IN condition delete, got {gone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
