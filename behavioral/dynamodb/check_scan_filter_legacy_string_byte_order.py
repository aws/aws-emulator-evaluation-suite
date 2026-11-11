"""scan-filter-legacy-string-byte-order."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-legacy-string-byte-order"
GROUP = "scan"
SERVICES = ["dynamodb"]

#: Five rows: a byte-order column `s` (A=0x41, B=0x42, Z=0x5A, a=0x61, ab=0x61,0x62) and an
#: unrelated `tag` column for the CONTAINS case. Every expected set is derived from these.
_ROWS = (
    ("r1", "A", "apple"),
    ("r2", "B", "banana"),
    ("r3", "Z", "cherry"),
    ("r4", "a", "date"),
    ("r5", "ab", "elderberry"),
)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Legacy ScanFilter LE/LT/GE/GT/BETWEEN on an S attribute compare by UTF-8 byte order
    (lowercase sorts above uppercase, so "a" > "B"), and CONTAINS matches a substring.
    """
    ddb = ctx.client("dynamodb")
    name = _seed(ctx)

    def scan_ids(scan_filter):
        resp = ddb.scan(TableName=name, ScanFilter=scan_filter, ConsistentRead=True)
        return sorted(i["id"]["S"] for i in resp["Items"])

    le = scan_ids({"s": {"AttributeValueList": [{"S": "B"}], "ComparisonOperator": "LE"}})
    assert le == ["r1", "r2"], f"LE 'B' returned {le!r}, expected ['r1', 'r2'] (s<='B': A, B)"

    lt = scan_ids({"s": {"AttributeValueList": [{"S": "B"}], "ComparisonOperator": "LT"}})
    assert lt == ["r1"], f"LT 'B' returned {lt!r}, expected ['r1'] (s<'B': A only)"

    ge = scan_ids({"s": {"AttributeValueList": [{"S": "Z"}], "ComparisonOperator": "GE"}})
    assert ge == ["r3", "r4", "r5"], (
        f"GE 'Z' returned {ge!r}, expected ['r3', 'r4', 'r5'] (s>='Z': Z, a, ab; lowercase sorts "
        f"above uppercase)"
    )

    gt = scan_ids({"s": {"AttributeValueList": [{"S": "B"}], "ComparisonOperator": "GT"}})
    assert gt == ["r3", "r4", "r5"], (
        f"GT 'B' returned {gt!r}, expected ['r3', 'r4', 'r5'] (s>'B': Z, a, ab)"
    )

    between = scan_ids({"s": {"AttributeValueList": [{"S": "B"}, {"S": "Z"}],
                               "ComparisonOperator": "BETWEEN"}})
    assert between == ["r2", "r3"], (
        f"BETWEEN 'B' and 'Z' returned {between!r}, expected ['r2', 'r3'] (inclusive: B, Z; 'a' and "
        f"'ab' sort above 'Z' and are excluded)"
    )

    contains = scan_ids({"tag": {"AttributeValueList": [{"S": "an"}], "ComparisonOperator": "CONTAINS"}})
    assert contains == ["r2"], (
        f"CONTAINS 'an' on tag returned {contains!r}, expected ['r2'] ('banana' is the only tag "
        f"holding the substring 'an')"
    )


def _seed(ctx) -> str:
    """A fresh table under a minted name, seeded with the five rows via one BatchWriteItem."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-ddbsbo-")
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    items = [{"PutRequest": {"Item": {"id": {"S": rid}, "s": {"S": s}, "tag": {"S": tag}}}}
             for rid, s, tag in _ROWS]
    resp = ddb.batch_write_item(RequestItems={name: items})
    assert resp["UnprocessedItems"] == {}, (
        f"seeding BatchWriteItem left {resp['UnprocessedItems']!r} unprocessed"
    )
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
