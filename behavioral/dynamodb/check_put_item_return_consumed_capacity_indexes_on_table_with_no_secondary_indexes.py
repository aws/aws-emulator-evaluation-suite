"""put-item-return-consumed-capacity-indexes-on-table-with-no-secondary-indexes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-item-return-consumed-capacity-indexes-on-table-with-no-secondary-indexes"
GROUP = "capacity"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """On a table with no secondary index, PutItem's ReturnConsumedCapacity=INDEXES reports only
    the Table arm, with no GlobalSecondaryIndexes or LocalSecondaryIndexes map at all."""
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    key = {"pk": {"S": "a"}, "sk": {"S": "1"}}
    cc = ddb.put_item(
        TableName=table, Item={**key, "attr1": {"S": "one"}}, ReturnConsumedCapacity="INDEXES",
    )["ConsumedCapacity"]

    assert cc.get("Table", {}).get("CapacityUnits") == 1.0, (
        f"the table arm's CapacityUnits was {cc.get('Table')!r}, expected 1.0"
    )
    assert "GlobalSecondaryIndexes" not in cc, (
        f"a table with no GSI reported a GlobalSecondaryIndexes arm: {cc.get('GlobalSecondaryIndexes')!r}"
    )
    assert "LocalSecondaryIndexes" not in cc, (
        f"a table with no LSI reported a LocalSecondaryIndexes arm: {cc.get('LocalSecondaryIndexes')!r}"
    )
    assert cc.get("CapacityUnits") == cc["Table"]["CapacityUnits"], (
        f"the total {cc.get('CapacityUnits')!r} must equal the table arm {cc['Table']['CapacityUnits']!r} "
        f"when no index arm is present"
    )

    read_back = ddb.get_item(TableName=table, Key=key, ConsistentRead=True).get("Item") or {}
    assert read_back.get("attr1", {}).get("S") == "one", f"the write did not persist: {read_back!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
