"""scan-filter-eq-and-contains-type-strict-across-s-n-b."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scan-filter-eq-and-contains-type-strict-across-s-n-b"
GROUP = "expressions"
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


def _ids(items) -> frozenset:
    return frozenset(i["pk"]["S"] for i in items)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan FilterExpression `=` matches an N, S or B attribute only against the identically
    typed operand, never the other two holding the same digits; `contains()` with an N operand
    matches an NS member or an N element inside an L, never an S, SS or B holding the same digits.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-ddbts-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=t), "ResourceNotFoundException"))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    ddb.put_item(TableName=t, Item={"pk": {"S": "eq-n"}, "val": {"N": "5"}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "eq-s"}, "val": {"S": "5"}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "eq-b"}, "val": {"B": b"5"}})

    ddb.put_item(TableName=t, Item={"pk": {"S": "coll-ns"}, "coll": {"NS": ["5", "6"]}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "coll-l"}, "coll": {"L": [{"N": "5"}, {"S": "x"}]}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "coll-s"}, "coll": {"S": "a5b"}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "coll-ss"}, "coll": {"SS": ["5", "6"]}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "coll-b"}, "coll": {"B": b"5"}})

    def scan(**kwargs) -> frozenset:
        return _ids(ddb.scan(TableName=t, ConsistentRead=True, **kwargs)["Items"])

    eq_n = scan(FilterExpression="val = :v", ExpressionAttributeValues={":v": {"N": "5"}})
    assert eq_n == frozenset({"eq-n"}), (
        f"val = (N)'5' matched {sorted(eq_n)!r}, expected only the N-typed item"
    )
    eq_s = scan(FilterExpression="val = :v", ExpressionAttributeValues={":v": {"S": "5"}})
    assert eq_s == frozenset({"eq-s"}), (
        f"val = (S)'5' matched {sorted(eq_s)!r}, expected only the S-typed item"
    )
    eq_b = scan(FilterExpression="val = :v", ExpressionAttributeValues={":v": {"B": b"5"}})
    assert eq_b == frozenset({"eq-b"}), (
        f"val = (B)'5' matched {sorted(eq_b)!r}, expected only the B-typed item"
    )

    contains_n = scan(FilterExpression="contains(coll, :v)", ExpressionAttributeValues={":v": {"N": "5"}})
    assert contains_n == frozenset({"coll-ns", "coll-l"}), (
        f"contains(coll, (N)5) matched {sorted(contains_n)!r}, expected only the NS and L items "
        f"holding an N 5 member/element, never the S, SS or B items holding the same digits"
    )

    # Positive control: contains() over the correctly typed operand still matches the S, SS and B
    # items, proving the filtering mechanism discriminates by value, not merely by excluding N.
    contains_s = scan(FilterExpression="contains(coll, :v)", ExpressionAttributeValues={":v": {"S": "5"}})
    assert contains_s == frozenset({"coll-s", "coll-ss"}), (
        f"contains(coll, (S)'5') matched {sorted(contains_s)!r}, expected the S item (substring) "
        f"and the SS item (member), never the NS, L or B items"
    )
    contains_b = scan(FilterExpression="contains(coll, :v)", ExpressionAttributeValues={":v": {"B": b"5"}})
    assert contains_b == frozenset({"coll-b"}), (
        f"contains(coll, (B)'5') matched {sorted(contains_b)!r}, expected only the B item"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
