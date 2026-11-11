"""scan-filter-legacy-numeric-decimal-negative."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-legacy-numeric-decimal-negative"
GROUP = "scan"
SERVICES = ["dynamodb"]

#: Five rows with a decimal and negative N column `amount`. Every expected set is derived
#: from these numeric values, compared numerically rather than as strings.
_ROWS = (
    ("r1", "-5"),
    ("r2", "-1.5"),
    ("r3", "0.25"),
    ("r4", "3.75"),
    ("r5", "10"),
)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Legacy ScanFilter LE/LT/GE/GT/BETWEEN on an N attribute compare decimals and negatives
    numerically: -1.5 < 0.25 < 10.
    """
    ddb = ctx.client("dynamodb")
    name = _seed(ctx)

    def scan_ids(scan_filter):
        resp = ddb.scan(TableName=name, ScanFilter=scan_filter, ConsistentRead=True)
        return sorted(i["id"]["S"] for i in resp["Items"])

    le = scan_ids({"amount": {"AttributeValueList": [{"N": "0.25"}], "ComparisonOperator": "LE"}})
    assert le == ["r1", "r2", "r3"], (
        f"LE 0.25 returned {le!r}, expected ['r1', 'r2', 'r3'] (amount<=0.25: -5, -1.5, 0.25)"
    )

    lt = scan_ids({"amount": {"AttributeValueList": [{"N": "0.25"}], "ComparisonOperator": "LT"}})
    assert lt == ["r1", "r2"], f"LT 0.25 returned {lt!r}, expected ['r1', 'r2'] (amount<0.25: -5, -1.5)"

    ge = scan_ids({"amount": {"AttributeValueList": [{"N": "3.75"}], "ComparisonOperator": "GE"}})
    assert ge == ["r4", "r5"], f"GE 3.75 returned {ge!r}, expected ['r4', 'r5'] (amount>=3.75: 3.75, 10)"

    gt = scan_ids({"amount": {"AttributeValueList": [{"N": "0.25"}], "ComparisonOperator": "GT"}})
    assert gt == ["r4", "r5"], f"GT 0.25 returned {gt!r}, expected ['r4', 'r5'] (amount>0.25: 3.75, 10)"

    between = scan_ids({"amount": {"AttributeValueList": [{"N": "-1.5"}, {"N": "3.75"}],
                                    "ComparisonOperator": "BETWEEN"}})
    assert between == ["r2", "r3", "r4"], (
        f"BETWEEN -1.5 and 3.75 returned {between!r}, expected ['r2', 'r3', 'r4'] (inclusive: "
        f"-1.5, 0.25, 3.75)"
    )


def _seed(ctx) -> str:
    """A fresh table under a minted name, seeded with the five rows via one BatchWriteItem."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-ddbnd-")
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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
