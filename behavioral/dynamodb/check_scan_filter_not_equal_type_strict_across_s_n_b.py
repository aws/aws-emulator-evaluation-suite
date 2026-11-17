"""scan-filter-not-equal-type-strict-across-s-n-b."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "scan-filter-not-equal-type-strict-across-s-n-b"
GROUP = "expressions"
SERVICES = ["dynamodb"]


def _ids(items) -> frozenset:
    return frozenset(i["pk"]["S"] for i in items)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Scan FilterExpression `<>` against an N, S or B operand matches the other two
    identically-digited items holding a different type, and excludes only the item whose
    type and value both match the operand.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-ddbne-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    ddb.put_item(TableName=t, Item={"pk": {"S": "val-n"}, "val": {"N": "5"}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "val-s"}, "val": {"S": "5"}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "val-b"}, "val": {"B": b"5"}})

    def scan(operand) -> frozenset:
        resp = ddb.scan(
            TableName=t,
            ConsistentRead=True,
            FilterExpression="val <> :v",
            ExpressionAttributeValues={":v": operand},
        )
        return _ids(resp["Items"])

    ne_n = scan({"N": "5"})
    assert ne_n == frozenset({"val-s", "val-b"}), (
        f"val <> (N)'5' matched {sorted(ne_n)!r}, expected the S and B items holding the same "
        f"digits, never the N item whose type and value both match"
    )
    ne_s = scan({"S": "5"})
    assert ne_s == frozenset({"val-n", "val-b"}), (
        f"val <> (S)'5' matched {sorted(ne_s)!r}, expected the N and B items holding the same "
        f"digits, never the S item whose type and value both match"
    )
    ne_b = scan({"B": b"5"})
    assert ne_b == frozenset({"val-n", "val-s"}), (
        f"val <> (B)'5' matched {sorted(ne_b)!r}, expected the N and S items holding the same "
        f"digits, never the B item whose type and value both match"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
