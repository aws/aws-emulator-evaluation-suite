"""ddb-numeric-sort-key-query-orders-at-magnitude-extremes."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "ddb-numeric-sort-key-query-orders-at-magnitude-extremes"
GROUP = "query"
SERVICES = ["dynamodb"]

# Four sort-key values spanning the documented N range from its negative ceiling down past
# zero to its smallest positive magnitude, then up to a large ordinary integer, IN ASCENDING
# numeric order:
#   -9.9999999999999999999999999999999999999E+125 < 0 < 1E-130 < 99999999999999999999999999999999999999
# A store that orders lexicographically on the stored string, or treats the extremes as equal
# to zero, disagrees with this sequence.
_ROWS = (
    ("neg-ceiling", "-9.9999999999999999999999999999999999999E+125"),
    ("zero", "0"),
    ("tiny-positive", "1E-130"),
    ("large-integer", "99999999999999999999999999999999999999"),
)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query orders an N sort key by numeric value at the documented magnitude extremes: the
    negative ceiling sorts first, then zero, then the smallest positive magnitude, then an
    ordinary large integer; ScanIndexForward=false reverses that order.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "N"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Write in an order that is neither ascending nor descending, so a store that merely
    # echoes insertion order also fails.
    for label, sk in (_ROWS[2], _ROWS[0], _ROWS[3], _ROWS[1]):
        ddb.put_item(TableName=table, Item={"pk": {"S": "mag"}, "sk": {"N": sk}, "label": {"S": label}})

    # The canonical stored string for each sk, read back independently of Query order: the
    # order assertion below compares against these, never against a numeric value.
    canonical = {}
    for label, sk in _ROWS:
        item = ddb.get_item(
            TableName=table, Key={"pk": {"S": "mag"}, "sk": {"N": sk}}, ConsistentRead=True,
        )["Item"]
        assert item["label"] == {"S": label}, (
            f"GetItem for {label!r} resolved the wrong item, got label {item['label']!r}"
        )
        canonical[label] = item["sk"]["N"]

    expected_asc = [canonical[label] for label, _sk in _ROWS]
    ascending = ddb.query(
        TableName=table, ConsistentRead=True, ScanIndexForward=True,
        KeyConditionExpression="pk = :p",
        ExpressionAttributeValues={":p": {"S": "mag"}},
    )
    asc_sks = [it["sk"]["N"] for it in ascending["Items"]]
    assert asc_sks == expected_asc, (
        f"ascending Query must order the N sort key {expected_asc!r} from the negative ceiling "
        f"up through zero and the smallest positive magnitude to the large integer, got {asc_sks!r}"
    )

    descending = ddb.query(
        TableName=table, ConsistentRead=True, ScanIndexForward=False,
        KeyConditionExpression="pk = :p",
        ExpressionAttributeValues={":p": {"S": "mag"}},
    )
    desc_sks = [it["sk"]["N"] for it in descending["Items"]]
    assert desc_sks == list(reversed(expected_asc)), (
        f"ScanIndexForward=False must reverse the ascending order to {list(reversed(expected_asc))!r}, "
        f"got {desc_sks!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
