"""query-filter-not-over-missing-attribute-equality."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-filter-not-over-missing-attribute-equality"
GROUP = "query"
SERVICES = ["dynamodb"]

_PK = "pk"
_SK = "sk"
_PART = "p1"


def _seed(ctx) -> str:
    """A pk/sk table, one partition: i1 deleted=True, i2 deleted=False, i3/i4 no `deleted` at all."""
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": _PK, "KeyType": "HASH"}, {"AttributeName": _SK, "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": _PK, "AttributeType": "S"},
                              {"AttributeName": _SK, "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={_PK: {"S": _PART}, _SK: {"S": "i1"}, "deleted": {"BOOL": True}})
    ddb.put_item(TableName=table, Item={_PK: {"S": _PART}, _SK: {"S": "i2"}, "deleted": {"BOOL": False}})
    ddb.put_item(TableName=table, Item={_PK: {"S": _PART}, _SK: {"S": "i3"}})
    ddb.put_item(TableName=table, Item={_PK: {"S": _PART}, _SK: {"S": "i4"}})
    return table


def _query(ddb, table: str, expr: str) -> set:
    resp = ddb.query(
        TableName=table, ConsistentRead=True,
        KeyConditionExpression="#pk = :pk",
        ExpressionAttributeNames={"#pk": _PK, "#del": "deleted"},
        ExpressionAttributeValues={":pk": {"S": _PART}, ":true": {"BOOL": True}},
        FilterExpression=expr,
    )
    assert resp["ScannedCount"] == 4, (
        f"Query {expr!r} ScannedCount was {resp['ScannedCount']!r}, expected the partition's 4 "
        f"items regardless of the filter"
    )
    return {i[_SK]["S"] for i in resp["Items"]}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query FilterExpression comparison against a missing attribute evaluates false, so NOT
    over it is true: `NOT deleted = :true` keeps every item without `deleted`, not just `False`.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    table = _seed(ctx)

    positive = _query(ddb, table, "#del = :true")
    assert positive == {"i1"}, f"`deleted = true` returned {sorted(positive)!r}, expected ['i1']"

    negated = _query(ddb, table, "NOT #del = :true")
    assert negated == {"i2", "i3", "i4"}, (
        f"`NOT deleted = true` returned {sorted(negated)!r}, expected ['i2', 'i3', 'i4'] -- i2 has "
        f"deleted=False so the raw comparison is false and NOT flips it true; i3/i4 have no "
        f"`deleted` attribute at all, which also makes the raw comparison false"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
