"""query-filter-begins-with-binary-attribute."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-filter-begins-with-binary-attribute"
GROUP = "query"
SERVICES = ["dynamodb"]

#: Items in the queried partition: (sk, blob). Expected sets below are derived from the bytes.
_ROWS = (
    ("i1", b"\x01\xaa"),
    ("i2", b"\x01\xbb\x02"),
    ("i3", b"\x02\xaa"),
    ("i4", b"\x02\xbb"),
    ("i5", b"\x03"),
)


def _ids(items) -> frozenset:
    return frozenset(i["sk"]["S"] for i in items)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query's FilterExpression begins_with() on a non-key Binary attribute selects items whose
    value shares the given byte prefix, over the whole partition it scans."""
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-ddbqfbw-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}, {"AttributeName": "sk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for sk, blob in _ROWS:
        ddb.put_item(TableName=t, Item={"pk": {"S": "p1"}, "sk": {"S": sk}, "blob": {"B": blob}})

    def _query_prefix(prefix: bytes) -> dict:
        return ddb.query(
            TableName=t,
            KeyConditionExpression="#pk = :pk",
            FilterExpression="begins_with(#b, :p)",
            ExpressionAttributeNames={"#pk": "pk", "#b": "blob"},
            ExpressionAttributeValues={":pk": {"S": "p1"}, ":p": {"B": prefix}},
            ConsistentRead=True,
        )

    cases = (
        (b"\x01", frozenset({"i1", "i2"})),
        (b"\x02", frozenset({"i3", "i4"})),
        (b"\x01\xaa", frozenset({"i1"})),
        (b"\x09", frozenset()),
    )
    for prefix, expected in cases:
        resp = _query_prefix(prefix)
        got = _ids(resp["Items"])
        assert got == expected, (
            f"begins_with(blob, {prefix!r}) returned {sorted(got)!r}, expected {sorted(expected)!r}"
        )
        assert resp["Count"] == len(expected), (
            f"begins_with(blob, {prefix!r}) Count was {resp['Count']!r}, expected {len(expected)!r}"
        )
        assert resp["ScannedCount"] == len(_ROWS), (
            f"begins_with(blob, {prefix!r}) ScannedCount was {resp['ScannedCount']!r}, expected "
            f"the partition's {len(_ROWS)} items regardless of the filter"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
