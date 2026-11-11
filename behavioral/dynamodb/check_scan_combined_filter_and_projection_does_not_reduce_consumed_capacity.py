"""scan-combined-filter-and-projection-does-not-reduce-consumed-capacity."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-combined-filter-and-projection-does-not-reduce-consumed-capacity"
GROUP = "capacity"
SERVICES = ["dynamodb"]

#: Five items, each its own partition; only two carry tag "match".
_ROWS = (
    {"pk": "i0", "tag": "match"},
    {"pk": "i1", "tag": "other"},
    {"pk": "i2", "tag": "match"},
    {"pk": "i3", "tag": "other"},
    {"pk": "i4", "tag": "other"},
)


def _item(row: dict) -> dict:
    return {"pk": {"S": row["pk"]}, "tag": {"S": row["tag"]}}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan's ConsumedCapacity with a FilterExpression and a ProjectionExpression together
    equals the unfiltered, unprojected scan: both act only after the item is read and billed."""
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t, KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    for row in _ROWS:
        ddb.put_item(TableName=t, Item=_item(row))

    baseline = ddb.scan(TableName=t, ConsistentRead=True, ReturnConsumedCapacity="TOTAL")
    assert baseline["Count"] == len(_ROWS) and baseline["ScannedCount"] == len(_ROWS), (
        f"the unfiltered scan must see every seeded item, got Count={baseline['Count']!r} "
        f"ScannedCount={baseline['ScannedCount']!r} over {len(_ROWS)} seeded"
    )

    combined = ddb.scan(
        TableName=t, ConsistentRead=True, ReturnConsumedCapacity="TOTAL",
        FilterExpression="#tg = :m", ProjectionExpression="#pk",
        ExpressionAttributeNames={"#tg": "tag", "#pk": "pk"},
        ExpressionAttributeValues={":m": {"S": "match"}},
    )
    assert combined["Count"] == 2, (
        f"the combined filter+projection scan matched {combined['Count']!r} items, expected 2"
    )
    assert combined["ScannedCount"] == len(_ROWS), (
        f"a filtered scan must still scan the whole table, got "
        f"ScannedCount={combined['ScannedCount']!r}, expected {len(_ROWS)}"
    )
    for item in combined["Items"]:
        assert set(item) == {"pk"}, f"the projected item had keys {sorted(item)}, expected only 'pk'"

    baseline_cu = baseline["ConsumedCapacity"]["CapacityUnits"]
    combined_cu = combined["ConsumedCapacity"]["CapacityUnits"]
    assert combined_cu == baseline_cu, (
        f"a scan combining FilterExpression and ProjectionExpression billed {combined_cu!r}, "
        f"the unfiltered unprojected scan billed {baseline_cu!r} -- neither must reduce the cost"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
