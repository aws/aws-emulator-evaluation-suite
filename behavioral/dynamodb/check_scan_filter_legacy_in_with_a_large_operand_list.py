"""scan-filter-legacy-in-with-a-large-operand-list."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-legacy-in-with-a-large-operand-list"
GROUP = "data-plane"
SERVICES = ["dynamodb"]

#: Five seeded records: (id, timestamp, status, category, score, name, email). Every expected
#: set is derived from these at run time, so a re-typed copy would silently weaken the check.
_ROWS = (
    ("user-001", "1700000000", "active", "premium", "95", "John Doe", "john@example.com"),
    ("user-002", "1700000001", "inactive", "basic", "67", "Jane Smith", "jane@example.com"),
    ("user-003", "1700000002", "pending", "standard", "78", "Bob Wilson", "bob@example.com"),
    ("user-004", "1700000003", "suspended", "basic", "45", "Alice Brown", "alice@example.com"),
    ("user-005", "1700000004", "active", "premium", "92", "Charlie Davis", "charlie@example.com"),
)

#: An IN operand list this long is far past the 100-operand cap FilterExpression IN enforces.
_OPERAND_COUNT = 27500


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A legacy ScanFilter IN AttributeValueList of 27500 operands is accepted and matches exactly
    the items holding the one listed value they carry; a FilterExpression read counts the same items.
    """
    ddb = ctx.client("dynamodb")
    name = _seed(ctx, "biglist")
    operands = [{"S": f"junk{i:05d}"} for i in range(_OPERAND_COUNT - 1)]
    operands.append({"S": "active"})
    res = ddb.scan(
        TableName=name, Select="COUNT", ConsistentRead=True,
        ScanFilter={"status": {"AttributeValueList": operands, "ComparisonOperator": "IN"}},
    )
    want = sum(1 for r in _ROWS if r[2] == "active")
    assert res["Count"] == want, (
        f"the {_OPERAND_COUNT}-operand ScanFilter IN matched {res['Count']!r}, expected {want}"
    )
    assert res["ScannedCount"] == len(_ROWS), (
        f"ScannedCount was {res['ScannedCount']!r}, expected {len(_ROWS)}"
    )
    control = ddb.scan(
        TableName=name, Select="COUNT", ConsistentRead=True,
        FilterExpression="#s = :v", ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":v": {"S": "active"}},
    )
    assert control["Count"] == want, (
        f"the FilterExpression positive control counted {control['Count']!r}, expected {want}"
    )


def _item(row) -> dict:
    """One seed row as a typed DynamoDB item: score and the sort key are numbers, the rest strings."""
    rid, stamp, status, category, score, name, email = row
    return {"id": {"S": rid}, "timestamp": {"N": stamp}, "status": {"S": status},
            "category": {"S": category}, "score": {"N": score}, "name": {"S": name},
            "email": {"S": email}}


def _seed(ctx, short: str) -> str:
    """A fresh table under a minted name, seeded with ONE BatchWriteItem."""
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name(f"sim2real-ddbss-{short}-")
    ddb.create_table(
        TableName=name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"},
                   {"AttributeName": "timestamp", "KeyType": "RANGE"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"},
                              {"AttributeName": "timestamp", "AttributeType": "N"}],
        BillingMode="PAY_PER_REQUEST",
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    resp = ddb.batch_write_item(RequestItems={name: [{"PutRequest": {"Item": _item(r)}} for r in _ROWS]})
    assert resp["UnprocessedItems"] == {}, (
        f"seeding BatchWriteItem left {resp['UnprocessedItems']!r} unprocessed"
    )
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
