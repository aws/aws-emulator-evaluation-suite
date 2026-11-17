"""lsi-query-sort-key-comparisons-return-full-item-body."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "lsi-query-sort-key-comparisons-return-full-item-body"
GROUP = "lsi"
SERVICES = ["dynamodb"]

#: (sk, lsiSk, payload) rows under one partition; lsiSk values sort lexically as written.
_ROWS = (
    ("rev-0", "d010", "alpha"),
    ("rev-1", "d020", "bravo"),
    ("rev-2", "d030", "charlie"),
    ("rev-3", "d040", "delta"),
    ("rev-4", "d050", "echo"),
    ("rev-5", "e010", "foxtrot"),
    ("rev-6", "e020", "golf"),
)


def _item(sk: str, lsi_sk: str, payload: str, seq: int) -> dict:
    return {
        "pk": {"S": "item-1"},
        "sk": {"S": sk},
        "lsiSk": {"S": lsi_sk},
        "payload": {"S": payload},
        "seq": {"N": str(seq)},
    }


def _expected(*indices: int) -> list:
    return [_item(*_ROWS[i], seq=i) for i in indices]


def _query(ddb, table: str, expr: str, values: dict) -> dict:
    return ddb.query(
        TableName=table, IndexName="lsi-ops", KeyConditionExpression=expr,
        ExpressionAttributeValues=values, ConsistentRead=True,
    )


def _assert_full_body(label: str, resp: dict, expected: list) -> None:
    assert resp["Items"] == expected, f"{label}: items were {resp['Items']!r}, expected {expected!r}"
    assert resp["Count"] == len(expected), f"{label}: Count was {resp['Count']}, expected {len(expected)}"
    assert resp["ScannedCount"] == len(expected), (
        f"{label}: ScannedCount was {resp['ScannedCount']}, expected {len(expected)}"
    )


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Query against an LSI with =, <, <=, >=, >, BETWEEN or begins_with on the sort key
    returns the complete matching item bodies, not merely their keys, in ascending index order.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-lsifull-")
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
            "Projection": {"ProjectionType": "ALL"},
        }],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    for seq, (sk, lsi_sk, payload) in enumerate(_ROWS):
        ddb.put_item(TableName=table, Item=_item(sk, lsi_sk, payload, seq))

    pk = {":pk": {"S": "item-1"}}

    eq = _query(ddb, table, "pk = :pk AND lsiSk = :v", {**pk, ":v": {"S": "d030"}})
    _assert_full_body("lsiSk = 'd030'", eq, _expected(2))

    lt = _query(ddb, table, "pk = :pk AND lsiSk < :v", {**pk, ":v": {"S": "d030"}})
    _assert_full_body("lsiSk < 'd030'", lt, _expected(0, 1))

    le = _query(ddb, table, "pk = :pk AND lsiSk <= :v", {**pk, ":v": {"S": "d030"}})
    _assert_full_body("lsiSk <= 'd030'", le, _expected(0, 1, 2))

    ge = _query(ddb, table, "pk = :pk AND lsiSk >= :v", {**pk, ":v": {"S": "d030"}})
    _assert_full_body("lsiSk >= 'd030'", ge, _expected(2, 3, 4, 5, 6))

    gt = _query(ddb, table, "pk = :pk AND lsiSk > :v", {**pk, ":v": {"S": "d030"}})
    _assert_full_body("lsiSk > 'd030'", gt, _expected(3, 4, 5, 6))

    between = _query(
        ddb, table, "pk = :pk AND lsiSk BETWEEN :lo AND :hi",
        {**pk, ":lo": {"S": "d020"}, ":hi": {"S": "d040"}},
    )
    _assert_full_body("lsiSk BETWEEN 'd020' AND 'd040'", between, _expected(1, 2, 3))

    begins = _query(ddb, table, "pk = :pk AND begins_with(lsiSk, :p)", {**pk, ":p": {"S": "e"}})
    _assert_full_body("begins_with(lsiSk, 'e')", begins, _expected(5, 6))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
