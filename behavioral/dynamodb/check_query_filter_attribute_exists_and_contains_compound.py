"""query-filter-attribute-exists-and-contains-compound."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-filter-attribute-exists-and-contains-compound"
GROUP = "query"
SERVICES = ["dynamodb"]

#: Items in the queried partition: (sk, desc, has_status). Expected sets below are derived from
#: these fields rather than hardcoded.
_ROWS = (
    ("i1", "notice of refund", True),
    ("i2", "international customs hold notice", False),
    ("i3", "late shipment update", True),
    ("i4", "notice", False),
    ("i5", "unrelated memo", True),
)


def _item(row: tuple) -> dict:
    sk, desc, has_status = row
    out = {"pk": {"S": "p1"}, "sk": {"S": sk}, "desc": {"S": desc}}
    if has_status:
        out["status"] = {"S": "active"}
    return out


def _ids(items) -> frozenset:
    return frozenset(i["sk"]["S"] for i in items)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query's FilterExpression `attribute_exists(#a) AND contains(#d, :v)` selects only items
    carrying the attribute whose other field also contains the substring, over the whole
    partition it scans."""
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-ddbqfac-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for row in _ROWS:
        ddb.put_item(TableName=t, Item=_item(row))

    expected = frozenset(sk for sk, desc, has_status in _ROWS if has_status and "notice" in desc)

    resp = ddb.query(
        TableName=t,
        KeyConditionExpression="#pk = :pk",
        FilterExpression="attribute_exists(#st) AND contains(#d, :v)",
        ExpressionAttributeNames={"#pk": "pk", "#st": "status", "#d": "desc"},
        ExpressionAttributeValues={":pk": {"S": "p1"}, ":v": {"S": "notice"}},
        ConsistentRead=True,
    )
    got = _ids(resp["Items"])
    assert got == expected, (
        f"attribute_exists(status) AND contains(desc, 'notice') returned {sorted(got)!r}, "
        f"expected {sorted(expected)!r}"
    )
    assert resp["Count"] == len(expected), (
        f"Count was {resp['Count']!r}, expected {len(expected)!r}"
    )
    assert resp["ScannedCount"] == len(_ROWS), (
        f"ScannedCount was {resp['ScannedCount']!r}, expected the partition's {len(_ROWS)} items "
        f"regardless of the filter"
    )

    # Positive control: the attribute_exists half alone matches every item carrying status,
    # proving the compound AND genuinely narrows rather than the contains() half alone deciding.
    exists_only = ddb.query(
        TableName=t,
        KeyConditionExpression="#pk = :pk",
        FilterExpression="attribute_exists(#st)",
        ExpressionAttributeNames={"#pk": "pk", "#st": "status"},
        ExpressionAttributeValues={":pk": {"S": "p1"}},
        ConsistentRead=True,
    )
    expected_exists_only = frozenset(sk for sk, desc, has_status in _ROWS if has_status)
    got_exists_only = _ids(exists_only["Items"])
    assert got_exists_only == expected_exists_only, (
        f"attribute_exists(status) alone returned {sorted(got_exists_only)!r}, expected "
        f"{sorted(expected_exists_only)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
