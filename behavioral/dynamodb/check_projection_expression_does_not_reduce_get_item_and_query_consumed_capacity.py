"""projection-expression-does-not-reduce-get-item-and-query-consumed-capacity."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "projection-expression-does-not-reduce-get-item-and-query-consumed-capacity"
GROUP = "capacity"
SERVICES = ["dynamodb"]

#: Sized so the whole item is exactly 9216 bytes (9 KiB): a strongly consistent read of it bills
#: exactly ceil(9216 / 4096) = 3.0 RCU, with or without a projection.
_BLOB_LEN = 9202


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ProjectionExpression that returns one attribute bills the same CapacityUnits as
    returning the whole item: GetItem and Query meter the item read, not the response.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-projcap-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=table, Item={
        "pk": {"S": "item"},
        "tag": {"S": "x"},
        "blob": {"S": "y" * _BLOB_LEN},
    })

    full_get = ddb.get_item(TableName=table, Key={"pk": {"S": "item"}},
                            ReturnConsumedCapacity="TOTAL", ConsistentRead=True)
    full_get_cap = full_get["ConsumedCapacity"]["CapacityUnits"]
    assert full_get_cap == 3.0, (
        f"a strongly consistent GetItem of the 9216-byte item billed {full_get_cap!r}, expected 3.0"
    )
    assert set(full_get["Item"]) == {"pk", "tag", "blob"}, (
        f"the unprojected GetItem returned keys {sorted(full_get['Item'])}, expected all three"
    )

    projected_get = ddb.get_item(TableName=table, Key={"pk": {"S": "item"}},
                                 ProjectionExpression="tag",
                                 ReturnConsumedCapacity="TOTAL", ConsistentRead=True)
    projected_get_cap = projected_get["ConsumedCapacity"]["CapacityUnits"]
    assert set(projected_get["Item"]) == {"tag"}, (
        f"the projected GetItem returned keys {sorted(projected_get['Item'])}, expected only 'tag'"
    )
    assert projected_get_cap == full_get_cap, (
        f"a one-attribute projection billed {projected_get_cap!r}, the unprojected read "
        f"{full_get_cap!r} -- a projection must not reduce GetItem capacity"
    )

    full_query = ddb.query(TableName=table, KeyConditionExpression="pk = :v",
                           ExpressionAttributeValues={":v": {"S": "item"}},
                           ReturnConsumedCapacity="TOTAL", ConsistentRead=True)
    full_query_cap = full_query["ConsumedCapacity"]["CapacityUnits"]
    assert full_query["Count"] == 1, f"the query matched {full_query['Count']} items, expected 1"
    assert full_query_cap == 3.0, (
        f"a strongly consistent Query of the 9216-byte item billed {full_query_cap!r}, expected 3.0"
    )
    assert set(full_query["Items"][0]) == {"pk", "tag", "blob"}, (
        f"the unprojected Query item had keys {sorted(full_query['Items'][0])}, expected all three"
    )

    projected_query = ddb.query(TableName=table, KeyConditionExpression="pk = :v",
                                ExpressionAttributeValues={":v": {"S": "item"}},
                                ProjectionExpression="tag",
                                ReturnConsumedCapacity="TOTAL", ConsistentRead=True)
    projected_query_cap = projected_query["ConsumedCapacity"]["CapacityUnits"]
    assert set(projected_query["Items"][0]) == {"tag"}, (
        f"the projected Query item had keys {sorted(projected_query['Items'][0])}, expected only 'tag'"
    )
    assert projected_query_cap == full_query_cap, (
        f"a one-attribute projection billed {projected_query_cap!r}, the unprojected query "
        f"{full_query_cap!r} -- a projection must not reduce Query capacity"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
