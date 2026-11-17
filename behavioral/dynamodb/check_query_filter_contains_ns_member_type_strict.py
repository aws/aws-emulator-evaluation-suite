"""query-filter-contains-ns-member-type-strict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "query-filter-contains-ns-member-type-strict"
GROUP = "query"
SERVICES = ["dynamodb"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _sks(items) -> frozenset:
    return frozenset(i["sk"]["S"] for i in items)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query FilterExpression `contains()` with an N operand matches an NS member or an N
    element inside an L, never an S, SS or B attribute holding the same digits.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-ddbqct-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=t), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    pk = "p1"
    ddb.put_item(TableName=t, Item={"pk": {"S": pk}, "sk": {"S": "coll-ns"}, "coll": {"NS": ["5", "6"]}})
    ddb.put_item(TableName=t, Item={"pk": {"S": pk}, "sk": {"S": "coll-l"}, "coll": {"L": [{"N": "5"}, {"S": "x"}]}})
    ddb.put_item(TableName=t, Item={"pk": {"S": pk}, "sk": {"S": "coll-s"}, "coll": {"S": "a5b"}})
    ddb.put_item(TableName=t, Item={"pk": {"S": pk}, "sk": {"S": "coll-ss"}, "coll": {"SS": ["5", "6"]}})
    ddb.put_item(TableName=t, Item={"pk": {"S": pk}, "sk": {"S": "coll-b"}, "coll": {"B": b"5"}})
    partition_size = 5

    def query(**kwargs) -> dict:
        return ddb.query(
            TableName=t, ConsistentRead=True,
            KeyConditionExpression="#pk = :pk",
            ExpressionAttributeNames={**kwargs.pop("ExpressionAttributeNames", {}), "#pk": "pk"},
            ExpressionAttributeValues={**kwargs.pop("ExpressionAttributeValues", {}), ":pk": {"S": pk}},
            **kwargs,
        )

    resp_n = query(FilterExpression="contains(coll, :v)", ExpressionAttributeValues={":v": {"N": "5"}})
    contains_n = _sks(resp_n["Items"])
    assert contains_n == frozenset({"coll-ns", "coll-l"}), (
        f"Query contains(coll, (N)5) matched {sorted(contains_n)!r}, expected only the NS and L "
        f"items holding an N 5 member/element, never the S, SS or B items holding the same digits"
    )
    assert resp_n["Count"] == 2, f"Query contains(coll, (N)5) Count was {resp_n['Count']!r}, expected 2"
    assert resp_n["ScannedCount"] == partition_size, (
        f"Query contains(coll, (N)5) ScannedCount was {resp_n['ScannedCount']!r}, expected the "
        f"partition's {partition_size} items regardless of the filter"
    )

    # Positive control: contains() over the correctly typed (S) operand still matches the S and
    # SS items, proving the filtering mechanism discriminates by value, not merely by excluding N.
    resp_s = query(FilterExpression="contains(coll, :v)", ExpressionAttributeValues={":v": {"S": "5"}})
    contains_s = _sks(resp_s["Items"])
    assert contains_s == frozenset({"coll-s", "coll-ss"}), (
        f"Query contains(coll, (S)'5') matched {sorted(contains_s)!r}, expected the S item "
        f"(substring) and the SS item (member), never the NS, L or B items"
    )

    resp_b = query(FilterExpression="contains(coll, :v)", ExpressionAttributeValues={":v": {"B": b"5"}})
    contains_b = _sks(resp_b["Items"])
    assert contains_b == frozenset({"coll-b"}), (
        f"Query contains(coll, (B)'5') matched {sorted(contains_b)!r}, expected only the B item"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
