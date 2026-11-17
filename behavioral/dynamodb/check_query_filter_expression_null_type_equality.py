"""query-filter-expression-null-type-equality."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-filter-expression-null-type-equality"
GROUP = "query"
SERVICES = ["dynamodb"]


def _make_table(ctx) -> str:
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"},
                   {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                              {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _ids(items) -> tuple:
    return tuple(sorted(i["sk"]["S"] for i in items))


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query's FilterExpression 'tag = :n' with a NULL-typed :n matches only items whose
    'tag' attribute is itself NULL-typed, not an item lacking 'tag' or holding another type.
    """
    ddb = ctx.client("dynamodb")
    t = _make_table(ctx)
    ddb.put_item(TableName=t, Item={"pk": {"S": "p1"}, "sk": {"S": "s0"}, "tag": {"NULL": True}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "p1"}, "sk": {"S": "s1"}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "p1"}, "sk": {"S": "s2"}, "tag": {"S": "x"}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "p1"}, "sk": {"S": "s3"}, "tag": {"NULL": True}})

    base = ddb.query(
        TableName=t, KeyConditionExpression="#pk = :pk",
        ExpressionAttributeNames={"#pk": "pk"}, ExpressionAttributeValues={":pk": {"S": "p1"}},
        ConsistentRead=True,
    )
    assert base["Count"] == 4 and base["ScannedCount"] == 4, (
        f"expected the unfiltered baseline to see all 4 seeded items, got "
        f"Count={base['Count']!r} ScannedCount={base['ScannedCount']!r}"
    )

    null_eq = ddb.query(
        TableName=t, KeyConditionExpression="#pk = :pk", FilterExpression="#t = :n",
        ExpressionAttributeNames={"#pk": "pk", "#t": "tag"},
        ExpressionAttributeValues={":pk": {"S": "p1"}, ":n": {"NULL": True}},
        ConsistentRead=True,
    )
    assert null_eq["ScannedCount"] == 4, (
        f"expected FilterExpression to examine all 4 items before filtering, got "
        f"ScannedCount={null_eq['ScannedCount']!r}"
    )
    assert null_eq["Count"] == 2, f"expected Count 2 for tag = NULL, got {null_eq['Count']!r}"
    assert _ids(null_eq["Items"]) == ("s0", "s3"), (
        f"tag = NULL matched {_ids(null_eq['Items'])!r}, expected exactly ('s0', 's3'): the item "
        f"missing 'tag' (s1) and the item whose 'tag' is a String (s2) must not match"
    )

    string_eq = ddb.query(
        TableName=t, KeyConditionExpression="#pk = :pk", FilterExpression="#t = :s",
        ExpressionAttributeNames={"#pk": "pk", "#t": "tag"},
        ExpressionAttributeValues={":pk": {"S": "p1"}, ":s": {"S": "x"}},
        ConsistentRead=True,
    )
    assert _ids(string_eq["Items"]) == ("s2",), (
        f"tag = :s with a String operand matched {_ids(string_eq['Items'])!r}, expected exactly "
        f"('s2',): the NULL-typed items (s0, s3) must not match a String comparand"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
