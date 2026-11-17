"""query-attribute-type-filter-selects-collection-and-null-types."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-attribute-type-filter-selects-collection-and-null-types"
GROUP = "query"
SERVICES = ["dynamodb"]

#: (sort key, attribute_type code, the AttributeValue stored under "attr") under test.
_CASES = (
    ("ns", "NS", {"NS": ["1", "2", "3"]}),
    ("bs", "BS", {"BS": [b"\x00\x01", b"\xff"]}),
    ("l", "L", {"L": [{"S": "a"}, {"N": "1"}]}),
    ("m", "M", {"M": {"x": {"S": "1"}, "y": {"N": "2"}}}),
    ("null", "NULL", {"NULL": True}),
    ("ss", "SS", {"SS": ["a", "b"]}),
)


def _unordered(item):
    """``item`` with each top-level set's members sorted; DynamoDB sets carry no member order."""
    if item is None:
        return None
    return {
        name: {kind: sorted(members)} if kind in ("SS", "NS", "BS") else {kind: members}
        for name, value in item.items() for kind, members in value.items()
    }


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query FilterExpression attribute_type(attr, :t) selects exactly the item whose stored
    attribute has type NS, BS, L, M, NULL or SS, and a missing attribute matches none of them.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-qdatyp-")
    ddb.create_table(
        TableName=table,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for sk, _type_code, val in _CASES:
        ddb.put_item(TableName=table, Item={"pk": {"S": "p1"}, "sk": {"S": sk}, "attr": val})
    ddb.put_item(TableName=table, Item={"pk": {"S": "p1"}, "sk": {"S": "missing"}})

    total = len(_CASES) + 1
    for sk, type_code, val in _CASES:
        resp = ddb.query(
            TableName=table, KeyConditionExpression="pk = :p",
            FilterExpression="attribute_type(#a, :t)",
            ExpressionAttributeNames={"#a": "attr"},
            ExpressionAttributeValues={":p": {"S": "p1"}, ":t": {"S": type_code}},
            ConsistentRead=True,
        )
        assert resp["ScannedCount"] == total, (
            f"type {type_code!r}: expected ScannedCount {total} (pre-filter), got {resp['ScannedCount']!r}"
        )
        assert resp["Count"] == 1, (
            f"type {type_code!r}: expected exactly one matching item, got Count {resp['Count']!r}"
        )
        item = resp["Items"][0]
        assert item["sk"] == {"S": sk}, (
            f"type {type_code!r}: expected the item at sk {sk!r} to match, got {item!r}"
        )
        assert _unordered({"attr": item["attr"]}) == _unordered({"attr": val}), (
            f"type {type_code!r}: returned attribute value {item['attr']!r}, expected {val!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
