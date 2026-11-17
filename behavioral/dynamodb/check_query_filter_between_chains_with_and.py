"""query-filter-between-chains-with-and."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-filter-between-chains-with-and"
GROUP = "query"
SERVICES = ["dynamodb"]

_PK = "pk"
_SK = "sk"
_PART = "p1"

#: sk, score, role, weight, chosen so BETWEEN's own AND never swallows a following clause.
_ITEMS = (
    ("i1", 5, "x", 50),
    ("i2", 12, "y", 40),
    ("i3", 20, "x", 30),
    ("i4", 30, "y", 20),
    ("i5", 25, "x", 10),
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
    for sk, score, role, weight in _ITEMS:
        ddb.put_item(TableName=table, Item={
            _PK: {"S": _PART}, _SK: {"S": sk}, "score": {"N": str(score)},
            "role": {"S": role}, "weight": {"N": str(weight)},
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
    """A Query FilterExpression's `x BETWEEN :lo AND :hi` closes at `:hi`: a logical AND that
    follows chains a separate clause rather than widening the BETWEEN's upper bound.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    table = _seed(ctx)

    one_clause = _query(
        ddb, table, "#sc BETWEEN :lo AND :hi AND #r = :r",
        {"#sc": "score", "#r": "role"},
        {":lo": {"N": "10"}, ":hi": {"N": "25"}, ":r": {"S": "x"}},
    )
    assert one_clause == {"i3", "i5"}, (
        f"`score BETWEEN 10 AND 25 AND role = x` returned {sorted(one_clause)!r}, expected "
        f"['i3', 'i5'] -- BETWEEN's AND closes at :hi, the following AND is a separate clause"
    )

    two_betweens = _query(
        ddb, table, "#sc BETWEEN :lo AND :hi AND #w BETWEEN :lo2 AND :hi2",
        {"#sc": "score", "#w": "weight"},
        {":lo": {"N": "10"}, ":hi": {"N": "25"}, ":lo2": {"N": "15"}, ":hi2": {"N": "35"}},
    )
    assert two_betweens == {"i3"}, (
        f"`score BETWEEN 10 AND 25 AND weight BETWEEN 15 AND 35` returned {sorted(two_betweens)!r}, "
        f"expected ['i3'] -- each BETWEEN keeps its own two-operand bound"
    )

    triple_chain = _query(
        ddb, table, "#sc BETWEEN :lo AND :hi AND #r = :r AND #w BETWEEN :lo2 AND :hi2",
        {"#sc": "score", "#r": "role", "#w": "weight"},
        {":lo": {"N": "10"}, ":hi": {"N": "25"}, ":r": {"S": "x"},
         ":lo2": {"N": "15"}, ":hi2": {"N": "35"}},
    )
    assert triple_chain == {"i3"}, (
        f"`score BETWEEN 10 AND 25 AND role = x AND weight BETWEEN 15 AND 35` returned "
        f"{sorted(triple_chain)!r}, expected ['i3']"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
