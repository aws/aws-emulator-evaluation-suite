"""scan-filter-expression-le-and-lt-on-numeric-decimals-and-negatives."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-expression-le-and-lt-on-numeric-decimals-and-negatives"
GROUP = "scan"
SERVICES = ["dynamodb"]

#: Five rows with a decimal and negative N column `amount`. Every expected set below is derived
#: from these numeric values, compared numerically rather than as strings.
_ROWS = (
    ("r1", "-5"),
    ("r2", "-1.5"),
    ("r3", "0.25"),
    ("r4", "3.75"),
    ("r5", "10"),
)


def _seed(ctx) -> str:
    """A fresh table under a minted name, seeded with the five rows via one BatchWriteItem."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-ddbfelt-")
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    items = [{"PutRequest": {"Item": {"id": {"S": rid}, "amount": {"N": amount}}}}
             for rid, amount in _ROWS]
    resp = ddb.batch_write_item(RequestItems={name: items})
    assert resp["UnprocessedItems"] == {}, (
        f"seeding BatchWriteItem left {resp['UnprocessedItems']!r} unprocessed"
    )
    return name


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan FilterExpression's <= and < on an N attribute compare decimals and negatives
    numerically, and each matches the legacy ScanFilter twin's set exactly.
    """
    ddb = ctx.client("dynamodb")
    name = _seed(ctx)

    def scan_ids(**kwargs) -> set:
        resp = ddb.scan(TableName=name, ConsistentRead=True, **kwargs)
        return {i["id"]["S"] for i in resp["Items"]}

    # <= on a decimal bound: amount <= 0.25 selects the two negatives plus the tied decimal.
    le_expected = {r[0] for r in _ROWS if float(r[1]) <= 0.25}
    fe_le = scan_ids(FilterExpression="amount <= :v", ExpressionAttributeValues={":v": {"N": "0.25"}})
    assert fe_le == le_expected, (
        f"FilterExpression 'amount <= 0.25' returned {fe_le!r}, expected {le_expected!r}"
    )
    legacy_le = scan_ids(ScanFilter={"amount": {"ComparisonOperator": "LE",
                                                 "AttributeValueList": [{"N": "0.25"}]}})
    assert legacy_le == fe_le, (
        f"legacy ScanFilter LE on amount returned {legacy_le!r}, must match FilterExpression's "
        f"{fe_le!r}"
    )

    # < on the same decimal bound: amount < 0.25 excludes the tied value, leaving only the negatives.
    lt_expected = {r[0] for r in _ROWS if float(r[1]) < 0.25}
    fe_lt = scan_ids(FilterExpression="amount < :v", ExpressionAttributeValues={":v": {"N": "0.25"}})
    assert fe_lt == lt_expected, (
        f"FilterExpression 'amount < 0.25' returned {fe_lt!r}, expected {lt_expected!r}"
    )
    legacy_lt = scan_ids(ScanFilter={"amount": {"ComparisonOperator": "LT",
                                                 "AttributeValueList": [{"N": "0.25"}]}})
    assert legacy_lt == fe_lt, (
        f"legacy ScanFilter LT on amount returned {legacy_lt!r}, must match FilterExpression's "
        f"{fe_lt!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
