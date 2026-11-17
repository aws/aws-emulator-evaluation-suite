"""transact-write-items-delete-of-absent-item-is-a-no-op-that-still-commits."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "transact-write-items-delete-of-absent-item-is-a-no-op-that-still-commits"
GROUP = "transactions"
SERVICES = ["dynamodb"]


def _table(ctx, ddb) -> str:
    name = ctx.unique_name("sim2real-behav-ddbtx-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _get(ddb, table, pk):
    return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems Delete with no ConditionExpression commits when its key has no item: the
    call succeeds with an empty body, the key stays absent, and a sibling Delete in the same
    transaction still removes the item it targets.
    """
    ddb = ctx.client("dynamodb")
    table = _table(ctx, ddb)

    ddb.put_item(TableName=table, Item={"pk": {"S": "existing"}, "v": {"S": "present"}})
    ddb.put_item(TableName=table, Item={"pk": {"S": "survivor"}, "v": {"S": "untouched"}})

    assert _get(ddb, table, "ghost") is None, "setup: 'ghost' must have no item before the transaction"
    assert _get(ddb, table, "existing") is not None, "setup: 'existing' must have an item before the transaction"

    resp = ddb.transact_write_items(TransactItems=[
        {"Delete": {"TableName": table, "Key": {"pk": {"S": "ghost"}}}},
        {"Delete": {"TableName": table, "Key": {"pk": {"S": "existing"}}}},
    ])
    body = {k: v for k, v in resp.items() if k != "ResponseMetadata"}
    assert body == {}, f"a TransactWriteItems of two unconditional Deletes returned a non-empty body: {body!r}"

    ghost_after = _get(ddb, table, "ghost")
    assert ghost_after is None, f"deleting an absent key must not create it, got {ghost_after!r}"

    existing_after = _get(ddb, table, "existing")
    assert existing_after is None, f"the sibling Delete of 'existing' must have applied, got {existing_after!r}"

    survivor = _get(ddb, table, "survivor")
    assert survivor == {"pk": {"S": "survivor"}, "v": {"S": "untouched"}}, (
        f"an item outside the transaction must be untouched, got {survivor!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
