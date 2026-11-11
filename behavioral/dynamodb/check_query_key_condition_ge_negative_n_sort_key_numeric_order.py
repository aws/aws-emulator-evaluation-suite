"""query-key-condition-ge-negative-n-sort-key-numeric-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-key-condition-ge-negative-n-sort-key-numeric-order"
GROUP = "query"
SERVICES = ["dynamodb"]

# sk values written out of numeric order; GE_THRESHOLD excludes the first two numerically.
_SKS = ["7", "-15", "0", "-10", "-3"]
_GE_THRESHOLD = "-10"
_EXPECTED_ASC = ["-10", "-3", "0", "7"]
_EXCLUDED_SK = "-15"


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query's sk >= :v on an N sort key selects and orders by numeric value, including a
    negative threshold's own boundary and excluding a more-negative key; ScanIndexForward=false
    reverses that order, and the excluded key is still present in the table.
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

    for sk in _SKS:
        ddb.put_item(TableName=table, Item={"pk": {"S": "row"}, "sk": {"N": sk}})

    ascending = ddb.query(
        TableName=table, ConsistentRead=True,
        KeyConditionExpression="pk = :p AND sk >= :v",
        ExpressionAttributeValues={":p": {"S": "row"}, ":v": {"N": _GE_THRESHOLD}},
    )
    asc_sks = [item["sk"]["N"] for item in ascending["Items"]]
    assert asc_sks == _EXPECTED_ASC, (
        f"sk >= {_GE_THRESHOLD} on an N sort key must select {_EXPECTED_ASC!r} in ascending "
        f"numeric order, got {asc_sks!r}"
    )
    assert ascending["Count"] == len(_EXPECTED_ASC), (
        f"expected Count={len(_EXPECTED_ASC)}, got {ascending['Count']!r}"
    )

    descending = ddb.query(
        TableName=table, ConsistentRead=True, ScanIndexForward=False,
        KeyConditionExpression="pk = :p AND sk >= :v",
        ExpressionAttributeValues={":p": {"S": "row"}, ":v": {"N": _GE_THRESHOLD}},
    )
    desc_sks = [item["sk"]["N"] for item in descending["Items"]]
    assert desc_sks == list(reversed(_EXPECTED_ASC)), (
        f"ScanIndexForward=False must reverse the order to {list(reversed(_EXPECTED_ASC))!r}, "
        f"got {desc_sks!r}"
    )

    excluded = ddb.get_item(
        TableName=table, Key={"pk": {"S": "row"}, "sk": {"N": _EXCLUDED_SK}}, ConsistentRead=True,
    )
    assert excluded.get("Item", {}).get("sk") == {"N": _EXCLUDED_SK}, (
        f"the key below the GE threshold must still exist in the table, got {excluded.get('Item')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
