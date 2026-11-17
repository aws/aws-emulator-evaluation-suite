"""scan-filter-attribute-type-matches-collection-and-set-types."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-attribute-type-matches-collection-and-set-types"
GROUP = "data-plane"
SERVICES = ["dynamodb"]

#: pk -> the AttributeValue stored under "val", one per attribute_type code under test plus
#: three scalar decoys and one item that lacks the attribute entirely.
_ITEMS = {
    "item-bs": {"BS": [b"\x01", b"\x02\x03"]},
    "item-l": {"L": [{"S": "x"}, {"N": "1"}]},
    "item-ns": {"NS": ["1", "2", "3"]},
    "item-ss": {"SS": ["a", "b"]},
    "item-s": {"S": "hello"},
    "item-n": {"N": "5"},
    "item-bool": {"BOOL": True},
}

#: The four codes under test; every expected set below is derived from `_ITEMS`, never typed.
_CODES = ("BS", "L", "NS", "SS")


def _make_table(ctx) -> str:
    """An on-demand table keyed by pk (S) HASH only."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-ddbat-")
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 90})
    return name


def _seed(ctx, name: str) -> None:
    ddb = ctx.client("dynamodb")
    for pk, val in _ITEMS.items():
        ddb.put_item(TableName=name, Item={"pk": {"S": pk}, "val": val})
    ddb.put_item(TableName=name, Item={"pk": {"S": "item-missing"}})


def _typed_pks(ddb, name: str, code: str) -> frozenset:
    """Every page of a strongly consistent Scan filtered on attribute_type(val, code)."""
    items, start = [], None
    while True:
        extra = {"ExclusiveStartKey": start} if start else {}
        page = ddb.scan(
            TableName=name, FilterExpression="attribute_type(#v, :t)",
            ExpressionAttributeNames={"#v": "val"}, ExpressionAttributeValues={":t": {"S": code}},
            ConsistentRead=True, **extra,
        )
        items.extend(page["Items"])
        start = page.get("LastEvaluatedKey")
        if not start:
            return frozenset(i["pk"]["S"] for i in items)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Scan's attribute_type(attr, code) matches exactly the item whose stored type is a Binary
    Set, List, Number Set or String Set, and excludes every item of a different stored type,
    including the three scalar types and the item that lacks the attribute.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-functions.attribute_type.html
    """
    ddb = ctx.client("dynamodb")
    name = _make_table(ctx)
    _seed(ctx, name)

    pk_of = {code: pk for pk, val in _ITEMS.items() for code in val if code in _CODES}

    for code in _CODES:
        got = _typed_pks(ddb, name, code)
        want = frozenset({pk_of[code]})
        assert got == want, f"attribute_type(val, {code!r}) returned {sorted(got)!r}, expected {sorted(want)!r}"

    # Positive control: the four matches partition exactly against the scalar types and the
    # item with no `val` attribute at all -- none of those four other items shows up under any
    # of the four collection/set codes.
    union = frozenset().union(*(_typed_pks(ddb, name, code) for code in _CODES))
    assert union == frozenset(pk_of[c] for c in _CODES), (
        f"the four collection/set codes together matched {sorted(union)!r}, "
        f"expected exactly {sorted(pk_of[c] for c in _CODES)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
