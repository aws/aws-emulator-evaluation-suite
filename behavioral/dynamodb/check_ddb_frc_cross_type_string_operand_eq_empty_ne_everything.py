"""ddb-frc-cross-type-string-operand-eq-empty-ne-everything."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "ddb-frc-cross-type-string-operand-eq-empty-ne-everything"
GROUP = "data-plane"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ResolvedAt (N) = :s and <> :s with :s an S of the same digits: '=' matches nothing and
    '<>' matches every item, because a cross-type AttributeValue is never equal.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.OperatorsAndFunctions.html
    """
    ddb = ctx.client("dynamodb")
    name = _make_table(ctx)
    _seed(ctx, name)

    def ids(expr, value):
        return _ids(_scan(ddb, name, FilterExpression=expr,
                          ExpressionAttributeValues={":v": value})["items"])

    same_type = ids("ResolvedAt = :v", {"N": "100"})
    assert same_type == ("item1",), f"ResolvedAt = 100 (N) returned {same_type!r}, expected ('item1',)"

    cross_eq = ids("ResolvedAt = :v", {"S": "100"})
    assert cross_eq == (), (
        f"ResolvedAt (N) = '100' (S) returned {cross_eq!r}; a cross-type AttributeValue never equals"
    )

    cross_ne = ids("ResolvedAt <> :v", {"S": "100"})
    assert cross_ne == _ALL, (
        f"ResolvedAt (N) <> '100' (S) returned {cross_ne!r}, expected every item with ResolvedAt: {_ALL!r}"
    )


# ===== inlined estate: seed =====
#: Three items, every one carrying ResolvedAt as a Number. :v's digits ('100') equal item1's value
#: as text, so a type-aware comparison and a lexicographic one would disagree if AWS compared loosely.
_SEED_ITEMS = (
    {"id": {"S": "item1"}, "ResolvedAt": {"N": "100"}},
    {"id": {"S": "item2"}, "ResolvedAt": {"N": "200"}},
    {"id": {"S": "item3"}, "ResolvedAt": {"N": "300"}},
)

#: Derived from the seed: every item's id, since every item carries ResolvedAt.
_ALL = tuple(sorted(i["id"]["S"] for i in _SEED_ITEMS))


def _make_table(ctx) -> str:
    """The table under a minted name: id (S) HASH, on demand."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-ddbfrc-xtype-")
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return name


def _seed(ctx, name: str, items=_SEED_ITEMS) -> None:
    """Seeds the table with ONE BatchWriteItem."""
    resp = ctx.client("dynamodb").batch_write_item(
        RequestItems={name: [{"PutRequest": {"Item": item}} for item in items]})
    assert resp["UnprocessedItems"] == {}, (
        f"BatchWriteItem left {resp['UnprocessedItems']!r} unprocessed while seeding"
    )


def _scan(ddb, name: str, **kwargs) -> dict:
    """Every page of a strongly consistent Scan: the items plus the summed Count."""
    out = {"items": [], "count": 0}
    start = None
    while True:
        extra = {"ExclusiveStartKey": start} if start else {}
        page = ddb.scan(TableName=name, ConsistentRead=True, **kwargs, **extra)
        out["items"].extend(page.get("Items", []))
        out["count"] += page["Count"]
        start = page.get("LastEvaluatedKey")
        if not start:
            return out


def _ids(items) -> tuple:
    return tuple(sorted(i["id"]["S"] for i in items))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
