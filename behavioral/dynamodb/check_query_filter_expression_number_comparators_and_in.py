"""query-filter-expression-number-comparators-and-in."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-filter-expression-number-comparators-and-in"
GROUP = "query"
SERVICES = ["dynamodb"]

#: Six items in one partition. Scores are chosen so a byte-wise string compare disagrees with
#: a numeric one ("9" > "10" and "100" < "11" as strings), so each case below only passes if
#: DynamoDB compares N values numerically.
_ROWS = (
    ("i1", "5"),
    ("i2", "9"),
    ("i3", "10"),
    ("i4", "11"),
    ("i5", "100"),
    ("i6", "200"),
)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query FilterExpression >=, <=, < and IN on a Number attribute compare the stored values
    numerically, selecting the items a numeric (not byte-wise) comparison predicts.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for sk, score in _ROWS:
        ddb.put_item(TableName=table, Item={"pk": {"S": "p1"}, "sk": {"S": sk}, "score": {"N": score}})

    readback = ddb.get_item(TableName=table, Key={"pk": {"S": "p1"}, "sk": {"S": "i5"}}, ConsistentRead=True)
    assert readback["Item"]["score"] == {"N": "100"}, (
        f"GetItem returned score {readback['Item']['score']!r}, expected the exact stored N string {{'N': '100'}}"
    )

    partition_size = len(_ROWS)
    cases = (
        ("#sc >= :v", {":v": {"N": "10"}}, {"i3", "i4", "i5", "i6"}),
        ("#sc <= :v", {":v": {"N": "10"}}, {"i1", "i2", "i3"}),
        ("#sc < :v", {":v": {"N": "11"}}, {"i1", "i2", "i3"}),
        ("#sc IN (:a, :b, :c)", {":a": {"N": "9"}, ":b": {"N": "11"}, ":c": {"N": "200"}}, {"i2", "i4", "i6"}),
    )
    for expr, values, expected in cases:
        resp = ddb.query(
            TableName=table, ConsistentRead=True,
            KeyConditionExpression="#pk = :pk",
            FilterExpression=expr,
            ExpressionAttributeNames={"#pk": "pk", "#sc": "score"},
            ExpressionAttributeValues={**values, ":pk": {"S": "p1"}},
        )
        got = {i["sk"]["S"] for i in resp["Items"]}
        assert got == expected, f"Query {expr!r} returned {sorted(got)}, expected {sorted(expected)}"
        assert resp["Count"] == len(expected), (
            f"Query {expr!r} Count was {resp['Count']}, expected {len(expected)}"
        )
        assert resp["ScannedCount"] == partition_size, (
            f"Query {expr!r} ScannedCount was {resp['ScannedCount']}, expected the partition's "
            f"{partition_size} items regardless of the filter"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
