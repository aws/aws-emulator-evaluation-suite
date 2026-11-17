"""query-filter-contains-empty-string-set-member-matches-the-holder."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-filter-contains-empty-string-set-member-matches-the-holder"
GROUP = "query"
SERVICES = ["dynamodb"]

_PK = "pk"
_SK = "sk"

#: Items in the queried partition; only `i2`'s roles set holds the empty-string member.
_P1 = "p1"
_P1_ITEMS = (
    {"sk": "i1", "roles": ["admin", "packer"]},
    {"sk": "i2", "roles": ["", "packer"]},
    {"sk": "i3", "roles": ["reader"]},
)

#: A different partition whose item also holds the empty member, proving the match stays
#: inside the queried partition rather than leaking in from elsewhere in the table.
_P2 = "p2"
_P2_ITEM = {"sk": "i4", "roles": ["", "x"]}


def _put(ddb, table: str, pk: str, item: dict) -> None:
    ddb.put_item(TableName=table, Item={
        "pk": {"S": pk}, "sk": {"S": item["sk"]}, "roles": {"SS": item["roles"]},
    })


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query FilterExpression contains(roles, '') matches the one item in the partition whose
    SS holds the empty-string member, leaving its non-holding partition siblings out."""
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": _PK, "KeyType": "HASH"}, {"AttributeName": _SK, "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": _PK, "AttributeType": "S"}, {"AttributeName": _SK, "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for item in _P1_ITEMS:
        _put(ddb, table, _P1, item)
    _put(ddb, table, _P2, _P2_ITEM)

    resp = ddb.query(
        TableName=table, ConsistentRead=True,
        KeyConditionExpression="#pk = :pk",
        FilterExpression="contains(#r, :empty)",
        ExpressionAttributeNames={"#pk": "pk", "#r": "roles"},
        ExpressionAttributeValues={":pk": {"S": _P1}, ":empty": {"S": ""}},
    )
    items = resp["Items"]
    assert resp["Count"] == 1, f"expected exactly one match in partition {_P1!r}, got Count={resp['Count']} Items={items!r}"
    assert items[0]["sk"]["S"] == "i2", f"expected the holder i2 to match, got {items[0]['sk']!r}"
    assert sorted(items[0]["roles"]["SS"]) == ["", "packer"], (
        f"the matched item's roles must still be the set it was written with, got {items[0]['roles']!r}"
    )
    assert resp["ScannedCount"] == len(_P1_ITEMS), (
        f"ScannedCount was {resp['ScannedCount']}, expected the partition's {len(_P1_ITEMS)} items "
        f"regardless of the filter"
    )

    got = ddb.get_item(TableName=table, Key={"pk": {"S": _P1}, "sk": {"S": "i1"}}, ConsistentRead=True)["Item"]
    assert sorted(got["roles"]["SS"]) == ["admin", "packer"], (
        f"i1's roles set must not hold the empty member and must be unaffected by the query, got {got['roles']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
