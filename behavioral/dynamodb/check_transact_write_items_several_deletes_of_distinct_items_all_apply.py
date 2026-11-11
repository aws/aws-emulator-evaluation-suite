"""transact-write-items-several-deletes-of-distinct-items-all-apply."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "transact-write-items-several-deletes-of-distinct-items-all-apply"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_KEYS = ("tx-del-a", "tx-del-b", "tx-del-c")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems holding several Deletes of distinct items commits every one: none
    of the deleted items is readable afterwards, and an item outside the transaction survives."""
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

    for key in _KEYS:
        ddb.put_item(TableName=table, Item={"pk": {"S": key}, "v": {"N": "1"}})
    ddb.put_item(TableName=table, Item={"pk": {"S": "tx-del-survivor"}, "v": {"N": "1"}})

    for key in _KEYS:
        before = ddb.get_item(TableName=table, Key={"pk": {"S": key}}, ConsistentRead=True).get("Item")
        assert before is not None, f"setup: {key!r} must exist before the transaction, got none"

    ddb.transact_write_items(TransactItems=[
        {"Delete": {"TableName": table, "Key": {"pk": {"S": key}}}} for key in _KEYS
    ])

    for key in _KEYS:
        after = ddb.get_item(TableName=table, Key={"pk": {"S": key}}, ConsistentRead=True).get("Item")
        assert after is None, f"{key!r} must be gone after the transaction deleted it, got {after!r}"

    survivor = ddb.get_item(TableName=table, Key={"pk": {"S": "tx-del-survivor"}},
                            ConsistentRead=True).get("Item")
    assert survivor == {"pk": {"S": "tx-del-survivor"}, "v": {"N": "1"}}, (
        f"an item outside the transaction must be untouched, got {survivor!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
