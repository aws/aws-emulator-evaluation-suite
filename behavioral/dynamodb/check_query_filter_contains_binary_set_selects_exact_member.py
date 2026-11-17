"""query-filter-contains-binary-set-selects-exact-member."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "query-filter-contains-binary-set-selects-exact-member"
GROUP = "expressions"
SERVICES = ["dynamodb"]


def _sks(items) -> frozenset:
    return frozenset(i["sk"]["S"] for i in items)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Query's FilterExpression contains(#bs, :v) on a Binary Set matches only the item whose
    set holds :v as one exact member, never an item whose members merely concatenate to it.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddbqbs-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    pk = "p"
    ddb.put_item(TableName=table, Item={
        "pk": {"S": pk}, "sk": {"S": "joined"}, "codes": {"BS": [b"\x01\x02", b"\x10"]},
    })
    ddb.put_item(TableName=table, Item={
        "pk": {"S": pk}, "sk": {"S": "split"}, "codes": {"BS": [b"\x01", b"\x02", b"\x20"]},
    })
    ddb.put_item(TableName=table, Item={
        "pk": {"S": pk}, "sk": {"S": "joined-too"}, "codes": {"BS": [b"\x01\x02"]},
    })
    ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "sk": {"S": "no-codes"}})

    def query(**kwargs) -> frozenset:
        resp = ddb.query(
            TableName=table, ConsistentRead=True,
            KeyConditionExpression="pk = :pk", **kwargs,
        )
        return _sks(resp["Items"])

    baseline = query(ExpressionAttributeValues={":pk": {"S": pk}})
    assert baseline == frozenset({"joined", "split", "joined-too", "no-codes"}), (
        f"unfiltered Query returned {sorted(baseline)!r}, expected all four items in the partition"
    )

    joined_match = query(
        FilterExpression="contains(#c, :v)",
        ExpressionAttributeNames={"#c": "codes"},
        ExpressionAttributeValues={":pk": {"S": pk}, ":v": {"B": b"\x01\x02"}},
    )
    assert joined_match == frozenset({"joined", "joined-too"}), (
        f"contains(codes, (B)x01x02) returned {sorted(joined_match)!r}, expected only the items "
        f"holding b'\\x01\\x02' as one member, never 'split' (which holds b'\\x01' and b'\\x02' "
        f"as two separate members) or 'no-codes' (which lacks the attribute)"
    )

    split_match = query(
        FilterExpression="contains(#c, :v)",
        ExpressionAttributeNames={"#c": "codes"},
        ExpressionAttributeValues={":pk": {"S": pk}, ":v": {"B": b"\x01"}},
    )
    assert split_match == frozenset({"split"}), (
        f"contains(codes, (B)x01) returned {sorted(split_match)!r}, expected only 'split' (whose "
        f"set holds the exact one-byte member), never 'joined' or 'joined-too' (whose member is "
        f"the two-byte string, not a match for the one-byte operand)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
