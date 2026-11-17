"""update-item-set-null-overwrites-scalar-type-and-creates-new-attribute."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-item-set-null-overwrites-scalar-type-and-creates-new-attribute"
GROUP = "scalar-types"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateExpression SET writes a top-level NULL-typed value both onto a brand new attribute
    and over an existing String one, and the stored type is exactly NULL, not a truthy stand-in.
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
    ddb.put_item(TableName=table, Item={**key, "note": {"S": "hello"}, "count": {"N": "3"}})

    new_values = ddb.update_item(
        TableName=table, Key=key,
        UpdateExpression="SET note = :null, extra = :null",
        ExpressionAttributeValues={":null": {"NULL": True}},
        ReturnValues="UPDATED_NEW",
    )["Attributes"]
    assert new_values == {"note": {"NULL": True}, "extra": {"NULL": True}}, (
        f"UpdateItem UPDATED_NEW: expected note and extra both NULL, got {new_values!r}"
    )

    got = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert got == {"pk": {"S": "x"}, "note": {"NULL": True}, "extra": {"NULL": True}, "count": {"N": "3"}}, (
        f"GetItem after SET to NULL: expected note/extra NULL and count untouched, got {got!r}"
    )

    # The stored type is exactly NULL: a condition that only an attribute_type NULL match
    # satisfies must pass for `extra`, proving it is typed NULL rather than merely absent-ish.
    ddb.update_item(
        TableName=table, Key=key,
        UpdateExpression="SET #c = #c + :one",
        ConditionExpression="attribute_type(extra, :t)",
        ExpressionAttributeNames={"#c": "count"},
        ExpressionAttributeValues={":one": {"N": "1"}, ":t": {"S": "NULL"}},
    )
    bumped = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert bumped["count"] == {"N": "4"}, (
        f"the conditional increment gated on attribute_type(extra, NULL) should have applied, "
        f"got count {bumped['count']!r}"
    )

    old_values = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="REMOVE note, extra",
        ReturnValues="UPDATED_OLD",
    )["Attributes"]
    assert old_values == {"note": {"NULL": True}, "extra": {"NULL": True}}, (
        f"UpdateItem UPDATED_OLD after REMOVE: expected both prior values NULL, got {old_values!r}"
    )

    final = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert final == {"pk": {"S": "x"}, "count": {"N": "4"}}, (
        f"GetItem after REMOVE: expected only pk and count left, got {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
