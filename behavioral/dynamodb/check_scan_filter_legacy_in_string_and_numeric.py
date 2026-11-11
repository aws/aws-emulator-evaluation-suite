"""scan-filter-legacy-in-string-and-numeric."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-legacy-in-string-and-numeric"
GROUP = "scan"
SERVICES = ["dynamodb"]

#: Five rows with an S column `status` and an N column `score`. The two IN lists exercised
#: below pick disjoint row sets so the two assertions cannot be satisfied by the same bug.
_ROWS = (
    ("r1", "active", "10"),
    ("r2", "inactive", "20.5"),
    ("r3", "pending", "30"),
    ("r4", "suspended", "40"),
    ("r5", "active", "50"),
)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """Legacy ScanFilter IN selects exactly the items whose S or N attribute equals one of the
    listed values.
    """
    ddb = ctx.client("dynamodb")
    name = _seed(ctx)

    def scan_ids(scan_filter):
        resp = ddb.scan(TableName=name, ScanFilter=scan_filter, ConsistentRead=True)
        return sorted(i["id"]["S"] for i in resp["Items"])

    in_s = scan_ids({"status": {"AttributeValueList": [{"S": "inactive"}, {"S": "suspended"}],
                                 "ComparisonOperator": "IN"}})
    assert in_s == ["r2", "r4"], (
        f"IN ('inactive','suspended') on status returned {in_s!r}, expected ['r2', 'r4']"
    )

    in_n = scan_ids({"score": {"AttributeValueList": [{"N": "10"}, {"N": "50"}],
                                "ComparisonOperator": "IN"}})
    assert in_n == ["r1", "r5"], (
        f"IN (10,50) on score returned {in_n!r}, expected ['r1', 'r5']"
    )


def _seed(ctx) -> str:
    """A fresh table under a minted name, seeded with the five rows via one BatchWriteItem."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-ddbin-")
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    items = [{"PutRequest": {"Item": {"id": {"S": rid}, "status": {"S": status},
                                       "score": {"N": score}}}}
             for rid, status, score in _ROWS]
    resp = ddb.batch_write_item(RequestItems={name: items})
    assert resp["UnprocessedItems"] == {}, (
        f"seeding BatchWriteItem left {resp['UnprocessedItems']!r} unprocessed"
    )
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
