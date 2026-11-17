"""update-add-creates-missing-number-set-and-unions-overlapping-binary-set."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "update-add-creates-missing-number-set-and-unions-overlapping-binary-set"
GROUP = "update-expression"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """UpdateItem ADD onto a Number Set the item lacks creates it with exactly the added
    members, and ADD onto an existing Binary Set unions in a member already present without
    duplicating it.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_UpdateItem.html
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

    key = {"pk": {"S": "item"}}
    ddb.put_item(TableName=table, Item={**key, "bins": {"BS": [b"aa", b"bb"]}})

    # ADD onto a Number Set that does not exist yet: the attribute is created from nothing.
    new = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD counts :v",
        ExpressionAttributeValues={":v": {"NS": ["5", "7"]}}, ReturnValues="UPDATED_NEW",
    ).get("Attributes")
    assert set(new["counts"]["NS"]) == {"5", "7"}, (
        f"ADD onto a missing Number Set must create it with exactly the added members, got {new['counts']!r}"
    )
    created = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert set(created["counts"]["NS"]) == {"5", "7"}, (
        f"the created Number Set must read back exactly the added members, got {created['counts']!r}"
    )
    assert set(created["bins"]["BS"]) == {b"aa", b"bb"}, (
        f"ADD on one attribute must leave the sibling Binary Set untouched, got {created['bins']!r}"
    )

    # ADD a Binary Set with one member already present: the union drops the duplicate.
    all_new = ddb.update_item(
        TableName=table, Key=key, UpdateExpression="ADD bins :v",
        ExpressionAttributeValues={":v": {"BS": [b"aa", b"cc"]}}, ReturnValues="ALL_NEW",
    ).get("Attributes")
    assert set(all_new["bins"]["BS"]) == {b"aa", b"bb", b"cc"}, (
        f"ADD with an overlapping Binary Set member must union without duplicating it, got {all_new['bins']!r}"
    )
    assert set(all_new["counts"]["NS"]) == {"5", "7"}, (
        f"ALL_NEW must still carry the sibling attribute unchanged, got {all_new['counts']!r}"
    )
    assert all_new["pk"] == key["pk"], f"ALL_NEW must still carry the key, got {all_new.get('pk')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
