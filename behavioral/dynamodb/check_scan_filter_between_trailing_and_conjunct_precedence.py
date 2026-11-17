"""scan-filter-between-trailing-and-conjunct-precedence."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-between-trailing-and-conjunct-precedence"
GROUP = "expressions"
SERVICES = ["dynamodb"]

#: Five items under an `id` (S) hash key: `price` (N) and `active` (BOOL) vary independently of
#: `category` (S), so each filter below isolates one clause's contribution to the match set.
_SEED_ITEMS = (
    {"id": {"S": "item1"}, "price": {"N": "15"}, "active": {"BOOL": True}, "category": {"S": "A"}},
    {"id": {"S": "item2"}, "price": {"N": "15"}, "active": {"BOOL": False}, "category": {"S": "A"}},
    {"id": {"S": "item3"}, "price": {"N": "5"}, "active": {"BOOL": True}, "category": {"S": "A"}},
    {"id": {"S": "item4"}, "price": {"N": "25"}, "active": {"BOOL": True}, "category": {"S": "A"}},
    {"id": {"S": "item5"}, "price": {"N": "15"}, "active": {"BOOL": True}, "category": {"S": "B"}},
)

_LO, _HI = "10", "20"
_BETWEEN_VALUES = {":lo": {"N": _LO}, ":hi": {"N": _HI}, ":true": {"BOOL": True}}
_BETWEEN_AND_CATEGORY_VALUES = {**_BETWEEN_VALUES, ":catA": {"S": "A"}}

#: Derived from the seed: price in [10, 20] AND active = true selects item1 and item5.
_BETWEEN_AND_ACTIVE = tuple(sorted(
    i["id"]["S"] for i in _SEED_ITEMS
    if int(_LO) <= int(i["price"]["N"]) <= int(_HI) and i["active"]["BOOL"]
))
#: The same two, further narrowed to category A: only item1.
_BETWEEN_AND_ACTIVE_AND_CATEGORY_A = tuple(sorted(
    i["id"]["S"] for i in _SEED_ITEMS
    if i["id"]["S"] in _BETWEEN_AND_ACTIVE and i["category"]["S"] == "A"
))


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan FilterExpression's BETWEEN clause, followed by a trailing AND conjunct, parses
    as (BETWEEN) AND (conjunct): the conjunct narrows the match set the same way regardless of
    which side of BETWEEN it sits on, and a further AND clause chains onto it the same way.
    """
    ddb = ctx.client("dynamodb")
    name = _make_table(ctx)
    _seed(ctx, name)

    trailing = _scan(ddb, name, FilterExpression="price BETWEEN :lo AND :hi AND active = :true",
                      ExpressionAttributeValues=_BETWEEN_VALUES)
    assert _ids(trailing["items"]) == _BETWEEN_AND_ACTIVE, (
        f"'price BETWEEN :lo AND :hi AND active = :true' returned {_ids(trailing['items'])!r}, "
        f"expected {_BETWEEN_AND_ACTIVE!r}"
    )

    leading = _scan(ddb, name, FilterExpression="active = :true AND price BETWEEN :lo AND :hi",
                     ExpressionAttributeValues=_BETWEEN_VALUES)
    assert _ids(leading["items"]) == _BETWEEN_AND_ACTIVE, (
        f"'active = :true AND price BETWEEN :lo AND :hi' returned {_ids(leading['items'])!r}, "
        f"expected {_BETWEEN_AND_ACTIVE!r} (same set as the conjunct trailing BETWEEN)"
    )

    chained = _scan(
        ddb, name,
        FilterExpression="price BETWEEN :lo AND :hi AND active = :true AND category = :catA",
        ExpressionAttributeValues=_BETWEEN_AND_CATEGORY_VALUES,
    )
    assert _ids(chained["items"]) == _BETWEEN_AND_ACTIVE_AND_CATEGORY_A, (
        f"'price BETWEEN :lo AND :hi AND active = :true AND category = :catA' returned "
        f"{_ids(chained['items'])!r}, expected {_BETWEEN_AND_ACTIVE_AND_CATEGORY_A!r}"
    )


def _make_table(ctx) -> str:
    """The table under a minted name: id (S) HASH, on demand."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-ddbbtwc-")
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
    """Every page of a strongly consistent Scan: the items plus the summed Count and ScannedCount.

    Paginated, because Count and ScannedCount are PER PAGE; strongly consistent, because an
    eventually consistent read straight after the seeding may legitimately come back short.
    """
    out = {"items": [], "count": 0, "scanned": 0, "pages": []}
    start = None
    while True:
        extra = {"ExclusiveStartKey": start} if start else {}
        page = ddb.scan(TableName=name, ConsistentRead=True, **kwargs, **extra)
        out["items"].extend(page.get("Items", []))
        out["count"] += page["Count"]
        out["scanned"] += page["ScannedCount"]
        out["pages"].append((page["Count"], page["ScannedCount"], "Items" in page))
        start = page.get("LastEvaluatedKey")
        if not start:
            return out


def _ids(items) -> tuple:
    return tuple(sorted(i["id"]["S"] for i in items))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
