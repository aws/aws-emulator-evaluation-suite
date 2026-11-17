"""scan-filter-contains-operand-type-matrix-legacy-and-expression."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-contains-operand-type-matrix-legacy-and-expression"
GROUP = "scan"
SERVICES = ["dynamodb"]


def _ids(items) -> frozenset:
    return frozenset(i["pk"]["S"] for i in items)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Legacy ScanFilter CONTAINS and FilterExpression contains() with an S, N or B operand each
    match only the identically typed scalar, the matching-type set's member, or an L element of
    that type, never a set or scalar of a different type holding the same digits.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-ddbcm-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=t, Item={"pk": {"S": "s"}, "coll": {"S": "5"}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "ss"}, "coll": {"SS": ["5", "6"]}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "ns"}, "coll": {"NS": ["5", "6"]}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "b"}, "coll": {"B": b"5"}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "bs"}, "coll": {"BS": [b"5", b"6"]}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "l"},
                                    "coll": {"L": [{"S": "5"}, {"N": "5"}, {"B": b"5"}]}})

    def legacy_contains(value: dict) -> frozenset:
        resp = ddb.scan(TableName=t, ConsistentRead=True,
                        ScanFilter={"coll": {"ComparisonOperator": "CONTAINS",
                                             "AttributeValueList": [value]}})
        return _ids(resp["Items"])

    def expr_contains(value: dict) -> frozenset:
        resp = ddb.scan(TableName=t, ConsistentRead=True,
                        FilterExpression="contains(coll, :v)",
                        ExpressionAttributeValues={":v": value})
        return _ids(resp["Items"])

    legacy_s = legacy_contains({"S": "5"})
    assert legacy_s == frozenset({"s", "ss", "l"}), (
        f"legacy CONTAINS with an S operand matched {sorted(legacy_s)!r}, expected the S "
        f"(substring), SS (member) and L (element) items, never NS, B or BS holding the same digits"
    )
    expr_s = expr_contains({"S": "5"})
    assert expr_s == legacy_s, (
        f"contains(coll, (S)'5') matched {sorted(expr_s)!r}, must match legacy CONTAINS's "
        f"{sorted(legacy_s)!r}"
    )

    legacy_n = legacy_contains({"N": "5"})
    assert legacy_n == frozenset({"ns", "l"}), (
        f"legacy CONTAINS with an N operand matched {sorted(legacy_n)!r}, expected only the NS "
        f"member and L element items, never S, SS, B or BS holding the same digits"
    )
    expr_n = expr_contains({"N": "5"})
    assert expr_n == legacy_n, (
        f"contains(coll, (N)5) matched {sorted(expr_n)!r}, must match legacy CONTAINS's "
        f"{sorted(legacy_n)!r}"
    )

    legacy_b = legacy_contains({"B": b"5"})
    assert legacy_b == frozenset({"b", "bs", "l"}), (
        f"legacy CONTAINS with a B operand matched {sorted(legacy_b)!r}, expected the B "
        f"(subsequence), BS (member) and L (element) items, never S, SS or NS holding the same digits"
    )
    expr_b = expr_contains({"B": b"5"})
    assert expr_b == legacy_b, (
        f"contains(coll, (B)b'5') matched {sorted(expr_b)!r}, must match legacy CONTAINS's "
        f"{sorted(legacy_b)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
