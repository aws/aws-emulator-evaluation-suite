"""query-filter-not-begins-with-or-precedence."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-filter-not-begins-with-or-precedence"
GROUP = "query"
SERVICES = ["dynamodb"]

_PK = "pk"
_SK = "sk"
_PART = "p1"

#: sk, desc, status, chosen so `NOT begins_with(...) OR ...` and `NOT (begins_with(...) OR ...)`
#: disagree.
_ITEMS = (
    ("i1", "alpha one", "A"),
    ("i2", "beta two", "B"),
    ("i3", "alpha three", "C"),
    ("i4", "gamma four", "D"),
    ("i5", "alpha five", "E"),
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
    for sk, desc, status in _ITEMS:
        ddb.put_item(TableName=table, Item={
            _PK: {"S": _PART}, _SK: {"S": sk}, "desc": {"S": desc}, "status": {"S": status},
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
    """A Query FilterExpression binds NOT tighter than OR: `NOT begins_with(...) OR ...` differs
    from `NOT (begins_with(...) OR ...)`, and OR still commutes around the NOT.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    table = _seed(ctx)
    names = {"#d": "desc", "#s": "status"}
    values = {":v": {"S": "alpha"}, ":d": {"S": "D"}}

    tight = _query(ddb, table, "NOT begins_with(#d, :v) OR #s = :d", names, values)
    assert tight == {"i2", "i4"}, (
        f"`NOT begins_with(desc, 'alpha') OR status = D` returned {sorted(tight)!r}, expected "
        f"['i2', 'i4'] -- NOT binds tighter than OR"
    )

    grouped = _query(ddb, table, "NOT (begins_with(#d, :v) OR #s = :d)", names, values)
    assert grouped == {"i2"}, (
        f"`NOT (begins_with(desc, 'alpha') OR status = D)` returned {sorted(grouped)!r}, "
        f"expected ['i2']"
    )

    swapped = _query(ddb, table, "#s = :d OR NOT begins_with(#d, :v)", names, values)
    assert swapped == tight, (
        f"`status = D OR NOT begins_with(desc, 'alpha')` returned {sorted(swapped)!r}, "
        f"expected {sorted(tight)!r}: OR commutes"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
