"""scan-filter-not-contains-operand-type-matrix-legacy-and-expression."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-not-contains-operand-type-matrix-legacy-and-expression"
GROUP = "scan"
SERVICES = ["dynamodb"]


def _ids(items) -> frozenset:
    return frozenset(i["pk"]["S"] for i in items)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Legacy ScanFilter NOT_CONTAINS and FilterExpression NOT contains() with an S, N or B
    operand exclude only the type-matched items that contain it, over a population mixing S,
    SS, NS, B and BS attributes of the same digits.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-ddbnc-")
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
    _all = frozenset({"s", "ss", "ns", "b", "bs"})

    def legacy_not_contains(value: dict) -> frozenset:
        resp = ddb.scan(TableName=t, ConsistentRead=True,
                        ScanFilter={"coll": {"ComparisonOperator": "NOT_CONTAINS",
                                             "AttributeValueList": [value]}})
        return _ids(resp["Items"])

    def expr_not_contains(value: dict) -> frozenset:
        resp = ddb.scan(TableName=t, ConsistentRead=True,
                        FilterExpression="NOT contains(coll, :v)",
                        ExpressionAttributeValues={":v": value})
        return _ids(resp["Items"])

    legacy_s = legacy_not_contains({"S": "5"})
    assert legacy_s == _all - frozenset({"s", "ss"}), (
        f"legacy NOT_CONTAINS with an S operand excluded {sorted(_all - legacy_s)!r}, expected "
        f"only the S (substring) and SS (member) items excluded"
    )
    expr_s = expr_not_contains({"S": "5"})
    assert expr_s == legacy_s, (
        f"'NOT contains(coll, (S)5)' returned {sorted(expr_s)!r}, must match legacy "
        f"NOT_CONTAINS's {sorted(legacy_s)!r} over a population with no missing attribute"
    )

    legacy_n = legacy_not_contains({"N": "5"})
    assert legacy_n == _all - frozenset({"ns"}), (
        f"legacy NOT_CONTAINS with an N operand excluded {sorted(_all - legacy_n)!r}, expected "
        f"only the NS member item excluded"
    )
    expr_n = expr_not_contains({"N": "5"})
    assert expr_n == legacy_n, (
        f"'NOT contains(coll, (N)5)' returned {sorted(expr_n)!r}, must match legacy "
        f"NOT_CONTAINS's {sorted(legacy_n)!r} over a population with no missing attribute"
    )

    legacy_b = legacy_not_contains({"B": b"5"})
    assert legacy_b == _all - frozenset({"b", "bs"}), (
        f"legacy NOT_CONTAINS with a B operand excluded {sorted(_all - legacy_b)!r}, expected "
        f"only the B (subsequence) and BS (member) items excluded"
    )
    expr_b = expr_not_contains({"B": b"5"})
    assert expr_b == legacy_b, (
        f"'NOT contains(coll, (B)b5)' returned {sorted(expr_b)!r}, must match legacy "
        f"NOT_CONTAINS's {sorted(legacy_b)!r} over a population with no missing attribute"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
