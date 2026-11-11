"""lsi-query-sort-key-comparison-and-prefix-operators."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "lsi-query-sort-key-comparison-and-prefix-operators"
GROUP = "lsi"
SERVICES = ["dynamodb"]

#: (sk, lsiSk) pairs under one partition; lsiSk values sort lexically as written.
_ROWS = (
    ("rev-0", "d010"),
    ("rev-1", "d020"),
    ("rev-2", "d030"),
    ("rev-3", "d040"),
    ("rev-4", "d050"),
    ("rev-5", "e010"),
    ("rev-6", "e020"),
)


def _query(ddb, table: str, expr: str, values: dict) -> list:
    resp = ddb.query(
        TableName=table, IndexName="lsi-ops", KeyConditionExpression=expr,
        ExpressionAttributeValues=values, ConsistentRead=True,
    )
    return [item["sk"]["S"] for item in resp["Items"]]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query against an LSI accepts =, <, <=, >=, BETWEEN and begins_with on the LSI sort
    key, each returning exactly the matching rows in ascending LSI sort key order.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-lsiops-")
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "lsiSk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        LocalSecondaryIndexes=[{
            "IndexName": "lsi-ops",
            "KeySchema": [
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "lsiSk", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "KEYS_ONLY"},
        }],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for sk, lsi_sk in _ROWS:
        ddb.put_item(TableName=table, Item={
            "pk": {"S": "item-1"}, "sk": {"S": sk}, "lsiSk": {"S": lsi_sk},
        })

    eq = _query(ddb, table, "pk = :pk AND lsiSk = :v", {":pk": {"S": "item-1"}, ":v": {"S": "d030"}})
    assert eq == ["rev-2"], f"lsiSk = 'd030' returned {eq!r}, expected ['rev-2']"

    lt = _query(ddb, table, "pk = :pk AND lsiSk < :v", {":pk": {"S": "item-1"}, ":v": {"S": "d030"}})
    assert lt == ["rev-0", "rev-1"], f"lsiSk < 'd030' returned {lt!r}, expected ['rev-0', 'rev-1']"

    le = _query(ddb, table, "pk = :pk AND lsiSk <= :v", {":pk": {"S": "item-1"}, ":v": {"S": "d030"}})
    assert le == ["rev-0", "rev-1", "rev-2"], (
        f"lsiSk <= 'd030' returned {le!r}, expected ['rev-0', 'rev-1', 'rev-2']"
    )

    ge = _query(ddb, table, "pk = :pk AND lsiSk >= :v", {":pk": {"S": "item-1"}, ":v": {"S": "d030"}})
    assert ge == ["rev-2", "rev-3", "rev-4", "rev-5", "rev-6"], (
        f"lsiSk >= 'd030' returned {ge!r}, expected ['rev-2', 'rev-3', 'rev-4', 'rev-5', 'rev-6']"
    )

    between = _query(
        ddb, table, "pk = :pk AND lsiSk BETWEEN :lo AND :hi",
        {":pk": {"S": "item-1"}, ":lo": {"S": "d020"}, ":hi": {"S": "d040"}},
    )
    assert between == ["rev-1", "rev-2", "rev-3"], (
        f"lsiSk BETWEEN 'd020' AND 'd040' returned {between!r}, expected ['rev-1', 'rev-2', 'rev-3']"
    )

    begins = _query(
        ddb, table, "pk = :pk AND begins_with(lsiSk, :p)",
        {":pk": {"S": "item-1"}, ":p": {"S": "e"}},
    )
    assert begins == ["rev-5", "rev-6"], (
        f"begins_with(lsiSk, 'e') returned {begins!r}, expected ['rev-5', 'rev-6']"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
