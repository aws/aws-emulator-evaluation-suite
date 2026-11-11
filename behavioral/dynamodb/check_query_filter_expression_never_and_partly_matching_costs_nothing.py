"""query-filter-expression-never-and-partly-matching-costs-nothing."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-filter-expression-never-and-partly-matching-costs-nothing"
GROUP = "query"
SERVICES = ["dynamodb"]

_ROWS = (
    ("o1", "pending"),
    ("o2", "complete"),
    ("o3", "pending"),
)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query's ConsumedCapacity and ScannedCount do not depend on its FilterExpression: a
    never-matching and a partly-matching filter report the same of both as no filter at all, and
    only Count drops. With no filter, ScannedCount equals Count.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbqf-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    for sk, status in _ROWS:
        ddb.put_item(TableName=table, Item={"pk": {"S": "u1"}, "sk": {"S": sk}, "status": {"S": status}})

    def _query(**extra) -> dict:
        return ddb.query(
            TableName=table,
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": {"S": "u1"}, **extra.pop("values", {})},
            ConsistentRead=True,
            ReturnConsumedCapacity="TOTAL",
            **extra,
        )

    unfiltered = _query()
    assert unfiltered["Count"] == len(_ROWS), (
        f"the unfiltered Query returned Count={unfiltered['Count']!r}, expected {len(_ROWS)!r}"
    )
    assert unfiltered["ScannedCount"] == unfiltered["Count"], (
        f"with no FilterExpression, ScannedCount={unfiltered['ScannedCount']!r} must equal "
        f"Count={unfiltered['Count']!r}"
    )
    base_cu = unfiltered["ConsumedCapacity"]["CapacityUnits"]
    base_scanned = unfiltered["ScannedCount"]

    never = _query(
        FilterExpression="#s = :never",
        ExpressionAttributeNames={"#s": "status"},
        values={":never": {"S": "archived"}},
    )
    assert never["Count"] == 0, (
        f"a FilterExpression matching no row must report Count=0, got {never['Count']!r}"
    )
    assert never["ScannedCount"] == base_scanned, (
        f"a never-matching filter changed ScannedCount to {never['ScannedCount']!r}, expected "
        f"the unfiltered {base_scanned!r}"
    )
    never_cu = never["ConsumedCapacity"]["CapacityUnits"]
    assert never_cu == base_cu, (
        f"a never-matching filter changed ConsumedCapacity to {never_cu!r}, expected the "
        f"unfiltered {base_cu!r}"
    )

    partly = _query(
        FilterExpression="#s = :p",
        ExpressionAttributeNames={"#s": "status"},
        values={":p": {"S": "pending"}},
    )
    expected_partial = sum(1 for _, status in _ROWS if status == "pending")
    assert partly["Count"] == expected_partial, (
        f"a partly-matching filter returned Count={partly['Count']!r}, expected {expected_partial!r}"
    )
    assert partly["ScannedCount"] == base_scanned, (
        f"a partly-matching filter changed ScannedCount to {partly['ScannedCount']!r}, expected "
        f"the unfiltered {base_scanned!r}"
    )
    partly_cu = partly["ConsumedCapacity"]["CapacityUnits"]
    assert partly_cu == base_cu, (
        f"a partly-matching filter changed ConsumedCapacity to {partly_cu!r}, expected the "
        f"unfiltered {base_cu!r}"
    )

    got_sks = sorted(item["sk"]["S"] for item in partly["Items"])
    want_sks = sorted(sk for sk, status in _ROWS if status == "pending")
    assert got_sks == want_sks, (
        f"the partly-matching filter returned items {got_sks!r}, expected {want_sks!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
