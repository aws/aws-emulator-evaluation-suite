"""query-filter-expression-operators-match-scan-twin-in-partition."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-filter-expression-operators-match-scan-twin-in-partition"
GROUP = "query"
SERVICES = ["dynamodb"]

_PK = "pk"
_SK = "sk"

#: Items in the queried partition. Each filter below is designed against these fields.
_P1 = "p1"
_P1_ITEMS = (
    {"sk": "i1", "desc": "fast shipping notice", "category": "alpha-priority",
     "roles": {"admin", "packer"}, "score": 5, "state": "placed"},
    {"sk": "i2", "desc": "international customs hold notice", "category": "beta-priority",
     "roles": {"packer"}, "score": 12, "state": "held"},
    {"sk": "i3", "desc": "notice of refund", "category": "alpha-priority",
     "roles": {"admin"}, "score": 20, "state": "placed"},
    {"sk": "i4", "desc": "late", "category": "gamma-priority",
     "roles": {"reader"}, "score": 30, "state": "shipped"},
    {"sk": "i5", "desc": "notice", "category": "alpha-priority",
     "roles": {"reader", "packer"}, "score": 25, "state": "returned"},
)

#: One item in a different partition that would match several filters below if it were in
#: `_P1`: used to prove the Query stays inside the queried partition.
_P2 = "p2"
_P2_ITEM = {"sk": "i6", "desc": "notice of notice", "category": "alpha-priority",
            "roles": {"admin"}, "score": 15, "state": "placed"}


def _put(ddb, table: str, pk: str, item: dict) -> None:
    ddb.put_item(TableName=table, Item={
        "pk": {"S": pk}, "sk": {"S": item["sk"]},
        "desc": {"S": item["desc"]}, "category": {"S": item["category"]},
        "roles": {"SS": sorted(item["roles"])},
        "score": {"N": str(item["score"])}, "state": {"S": item["state"]},
    })


def _skset(items) -> frozenset:
    return frozenset(i["sk"]["S"] for i in items)


def _scan_in_partition(ddb, table: str, pk: str, **kwargs) -> frozenset:
    """Every page of a strongly consistent Scan restricted (client-side) to `pk`."""
    out = []
    start = None
    while True:
        extra = {"ExclusiveStartKey": start} if start else {}
        page = ddb.scan(TableName=table, ConsistentRead=True, **kwargs, **extra)
        out.extend(i for i in page.get("Items", []) if i["pk"]["S"] == pk)
        start = page.get("LastEvaluatedKey")
        if not start:
            return _skset(out)


def _query_partition(ddb, table: str, pk: str, **kwargs) -> dict:
    resp = ddb.query(
        TableName=table, ConsistentRead=True,
        KeyConditionExpression="#pk = :pk",
        ExpressionAttributeNames={**kwargs.pop("ExpressionAttributeNames", {}), "#pk": "pk"},
        ExpressionAttributeValues={**kwargs.pop("ExpressionAttributeValues", {}), ":pk": {"S": pk}},
        **kwargs,
    )
    return resp


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query FilterExpression operators (contains, NOT contains, begins_with on a non-key
    attribute, BETWEEN, IN, a compound OR, size) select inside the queried partition exactly
    what the same FilterExpression on Scan selects there, with a fixed ScannedCount."""
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": _PK, "KeyType": "HASH"}, {"AttributeName": _SK, "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": _PK, "AttributeType": "S"}, {"AttributeName": _SK, "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for item in _P1_ITEMS:
        _put(ddb, table, _P1, item)
    _put(ddb, table, _P2, _P2_ITEM)

    partition_size = len(_P1_ITEMS)
    #: Every attribute name is aliased, whether or not it is a reserved word; each case lists
    #: only the aliases its own FilterExpression uses (an unused one is rejected).
    _ALL_NAMES = {"#d": "desc", "#r": "roles", "#c": "category", "#sc": "score", "#st": "state"}
    cases = (
        ("contains(#d, :v)", ("#d",), {":v": {"S": "notice"}}, {"i1", "i2", "i3", "i5"}),
        ("contains(#r, :v)", ("#r",), {":v": {"S": "admin"}}, {"i1", "i3"}),
        ("contains(#r, :v)", ("#r",), {":v": {"S": ""}}, set()),
        ("NOT contains(#r, :v)", ("#r",), {":v": {"S": "packer"}}, {"i3", "i4"}),
        ("begins_with(#c, :v)", ("#c",), {":v": {"S": "alpha"}}, {"i1", "i3", "i5"}),
        ("#sc BETWEEN :lo AND :hi", ("#sc",), {":lo": {"N": "10"}, ":hi": {"N": "25"}}, {"i2", "i3", "i5"}),
        ("#st IN (:a, :b)", ("#st",), {":a": {"S": "placed"}, ":b": {"S": "held"}}, {"i1", "i2", "i3"}),
        ("#st = :a OR #c = :b", ("#st", "#c"), {":a": {"S": "shipped"}, ":b": {"S": "beta-priority"}}, {"i2", "i4"}),
        ("size(#d) > :n", ("#d",), {":n": {"N": "15"}}, {"i1", "i2", "i3"}),
    )

    for expr, used, values, expected in cases:
        names = {k: _ALL_NAMES[k] for k in used}
        resp = _query_partition(
            ddb, table, _P1,
            FilterExpression=expr, ExpressionAttributeNames=dict(names), ExpressionAttributeValues=dict(values),
        )
        got = _skset(resp.get("Items", []))
        assert got == expected, f"Query {expr!r} in partition {_P1!r} returned {sorted(got)}, expected {sorted(expected)}"
        assert resp["Count"] == len(expected), f"Query {expr!r} Count was {resp['Count']}, expected {len(expected)}"
        assert resp["ScannedCount"] == partition_size, (
            f"Query {expr!r} ScannedCount was {resp['ScannedCount']}, expected the partition's "
            f"{partition_size} items regardless of the filter"
        )

        twin = _scan_in_partition(
            ddb, table, _P1,
            FilterExpression=expr, ExpressionAttributeNames=dict(names), ExpressionAttributeValues=dict(values),
        )
        assert got == twin, (
            f"Query {expr!r} returned {sorted(got)} but the Scan twin restricted to partition "
            f"{_P1!r} returned {sorted(twin)}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
