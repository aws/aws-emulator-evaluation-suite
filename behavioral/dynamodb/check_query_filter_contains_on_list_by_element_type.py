"""query-filter-contains-on-list-by-element-type."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-filter-contains-on-list-by-element-type"
GROUP = "query"
SERVICES = ["dynamodb"]

#: Items in the queried partition: (sk, list elements). Expected sets below are derived from
#: the typed members themselves, never hardcoded.
_ROWS = (
    ("i1", [{"N": "5"}, {"S": "x"}]),
    ("i2", [{"S": "5"}, {"S": "y"}]),
    ("i3", [{"N": "7"}]),
    ("i4", [{"S": "z"}]),
)


def _ids(items) -> frozenset:
    return frozenset(i["sk"]["S"] for i in items)


def _query_contains(ddb, table: str, value: dict) -> dict:
    return ddb.query(
        TableName=table,
        KeyConditionExpression="#pk = :pk",
        FilterExpression="contains(#c, :v)",
        ExpressionAttributeNames={"#pk": "pk", "#c": "coll"},
        ExpressionAttributeValues={":pk": {"S": "p1"}, ":v": value},
        ConsistentRead=True,
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query's FilterExpression contains(list_attr, :v) matches only items whose List holds a
    member of :v's exact type, whether :v is N or S, over the whole partition it scans."""
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-ddbqfcl-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for sk, coll in _ROWS:
        ddb.put_item(TableName=t, Item={"pk": {"S": "p1"}, "sk": {"S": sk}, "coll": {"L": coll}})

    expected_n = frozenset(sk for sk, coll in _ROWS if {"N": "5"} in coll)
    resp_n = _query_contains(ddb, t, {"N": "5"})
    got_n = _ids(resp_n["Items"])
    assert got_n == expected_n, (
        f"contains(coll, (N)'5') returned {sorted(got_n)!r}, expected {sorted(expected_n)!r}"
    )
    assert resp_n["Count"] == len(expected_n), (
        f"contains(coll, (N)'5') Count was {resp_n['Count']!r}, expected {len(expected_n)!r}"
    )
    assert resp_n["ScannedCount"] == len(_ROWS), (
        f"contains(coll, (N)'5') ScannedCount was {resp_n['ScannedCount']!r}, expected the "
        f"partition's {len(_ROWS)} items regardless of the filter"
    )

    expected_s = frozenset(sk for sk, coll in _ROWS if {"S": "5"} in coll)
    resp_s = _query_contains(ddb, t, {"S": "5"})
    got_s = _ids(resp_s["Items"])
    assert got_s == expected_s, (
        f"contains(coll, (S)'5') returned {sorted(got_s)!r}, expected {sorted(expected_s)!r}"
    )
    assert resp_s["Count"] == len(expected_s), (
        f"contains(coll, (S)'5') Count was {resp_s['Count']!r}, expected {len(expected_s)!r}"
    )
    assert resp_s["ScannedCount"] == len(_ROWS), (
        f"contains(coll, (S)'5') ScannedCount was {resp_s['ScannedCount']!r}, expected the "
        f"partition's {len(_ROWS)} items regardless of the filter"
    )

    assert got_n != got_s, (
        f"contains() with an N operand and an S operand of the same digits must select "
        f"different items; both returned {sorted(got_n)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
