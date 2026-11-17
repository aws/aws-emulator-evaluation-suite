"""query-filter-and-binds-tighter-than-or."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-filter-and-binds-tighter-than-or"
GROUP = "query"
SERVICES = ["dynamodb"]

_PK = "pk"
_SK = "sk"
_PART = "p1"

#: sk, status, category, score, chosen so `A OR B AND C` and `(A OR B) AND C` disagree.
_ITEMS = (
    ("i1", "active", "premium", 95),
    ("i2", "inactive", "basic", 67),
    ("i3", "pending", "standard", 78),
    ("i4", "suspended", "basic", 45),
    ("i5", "active", "premium", 92),
)


def _seed(ctx) -> str:
    """A pk/sk table with one partition seeded with ``_ITEMS``."""
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
    for sk, status, category, score in _ITEMS:
        ddb.put_item(TableName=table, Item={
            _PK: {"S": _PART}, _SK: {"S": sk}, "status": {"S": status},
            "category": {"S": category}, "score": {"N": str(score)},
        })
    return table


def _query(ddb, table: str, expr: str, names: dict, values: dict) -> set:
    resp = ddb.query(
        TableName=table, ConsistentRead=True,
        KeyConditionExpression="#pk = :pk",
        ExpressionAttributeNames={**names, "#pk": _PK},
        ExpressionAttributeValues={**values, ":pk": {"S": _PART}},
        FilterExpression=expr,
    )
    assert resp["ScannedCount"] == len(_ITEMS), (
        f"Query {expr!r} ScannedCount was {resp['ScannedCount']!r}, expected the partition's "
        f"{len(_ITEMS)} items regardless of the filter"
    )
    return {i[_SK]["S"] for i in resp["Items"]}


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query FilterExpression binds AND tighter than OR: `A OR B AND C` keeps only the
    suspended item while `(A OR B) AND C` keeps none.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    table = _seed(ctx)
    names = {"#s": "status"}
    values = {":su": {"S": "suspended"}, ":p": {"S": "pending"}, ":n": {"N": "80"}}

    implicit = _query(ddb, table, "#s = :su OR #s = :p AND score > :n", names, values)
    assert implicit == {"i4"}, (
        f"`A OR B AND C` returned {sorted(implicit)!r}, expected ['i4'] -- AND binds tighter than OR"
    )

    grouped = _query(ddb, table, "(#s = :su OR #s = :p) AND score > :n", names, values)
    assert grouped == set(), f"`(A OR B) AND C` returned {sorted(grouped)!r}, expected no record"

    both = _query(ddb, table, "#s = :a AND #c = :pr",
                  {"#s": "status", "#c": "category"},
                  {":a": {"S": "active"}, ":pr": {"S": "premium"}})
    assert both == {"i1", "i5"}, f"status AND category returned {sorted(both)!r}, expected ['i1', 'i5']"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
