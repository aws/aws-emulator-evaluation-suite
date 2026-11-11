"""update-item-numeric-set-precision-preserved."""
from __future__ import annotations

from decimal import Decimal

from behavioral_harness import tags

CHECK = "update-item-numeric-set-precision-preserved"
GROUP = "representation"
SERVICES = ["dynamodb"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Number Set updated via ADD retains exact numeric precision for every member,
    including a newly-added 38-significant-digit member, after UpdateItem."""
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx)

    pk = ctx.unique_name("item-")
    ddb.put_item(TableName=table, Item={"pk": {"S": pk}, "nums": {"NS": ["1.1"]}})

    big_num = "123456789012345678901234567890123456.78"  # 38 significant digits
    ddb.update_item(
        TableName=table,
        Key={"pk": {"S": pk}},
        UpdateExpression="ADD nums :n",
        ExpressionAttributeValues={":n": {"NS": [big_num]}},
    )

    resp = ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True)
    item = resp.get("Item")
    assert item is not None, "item not found after UpdateItem"
    members = item["nums"]["NS"]
    assert len(members) == 2, f"expected 2 set members, got {len(members)}"

    decimals = {Decimal(m) for m in members}
    assert Decimal("1.1") in decimals, "original member lost or altered"

    expected_big = Decimal(big_num)
    assert expected_big in decimals, (
        f"high-precision member not preserved exactly; members={members}"
    )


def _create_table(ctx):
    ddb = ctx.client("dynamodb")
    name = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ddb.get_waiter("table_exists").wait(TableName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=name))
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
