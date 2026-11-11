"""e2e-order-fulfillment-conditional-workflow."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-order-fulfillment-conditional-workflow"
GROUP = "e2e"
SERVICES = ["dynamodb"]

_TAGS_KV = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A conditional PutItem reservation, a conditional UpdateItem status change and a TransactWriteItems settlement
    leave the stock reduced by exactly the reserved quantity, the order FULFILLED and the reservation deleted.
    """
    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-fulfill-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=_TAGS_KV,
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    stock_key = "STOCK#sku-1"
    order_key = "ORDER#1"
    reservation_key = "RESERVATION#1"
    reserve_qty = 2
    initial_qty = 5

    ddb.put_item(
        TableName=table_name, Item={"pk": {"S": stock_key}, "quantity": {"N": str(initial_qty)}}
    )
    ddb.put_item(
        TableName=table_name,
        Item={"pk": {"S": order_key}, "status": {"S": "PENDING"}, "sku": {"S": stock_key}},
    )

    # Step 1: reserve stock via a conditional PutItem -- the hold record may only be created
    # once (guards against a duplicate reservation attempt for the same order).
    ddb.put_item(
        TableName=table_name,
        Item={
            "pk": {"S": reservation_key},
            "order": {"S": order_key},
            "qty": {"N": str(reserve_qty)},
            "status": {"S": "HELD"},
        },
        ConditionExpression="attribute_not_exists(pk)",
    )

    # Step 2: advance the order status, conditioned on it still being PENDING.
    ddb.update_item(
        TableName=table_name,
        Key={"pk": {"S": order_key}},
        UpdateExpression="SET #s = :new_status",
        ConditionExpression="#s = :expected_status",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":new_status": {"S": "RESERVED"}, ":expected_status": {"S": "PENDING"}},
    )

    # Step 3: atomic settlement -- decrement stock, flip the order to FULFILLED, and release the
    # reservation hold, all-or-nothing.
    ddb.transact_write_items(
        TransactItems=[
            {
                "Update": {
                    "TableName": table_name,
                    "Key": {"pk": {"S": stock_key}},
                    "UpdateExpression": "SET quantity = quantity - :qty",
                    "ConditionExpression": "quantity >= :qty",
                    "ExpressionAttributeValues": {":qty": {"N": str(reserve_qty)}},
                }
            },
            {
                "Update": {
                    "TableName": table_name,
                    "Key": {"pk": {"S": order_key}},
                    "UpdateExpression": "SET #s = :new_status",
                    "ConditionExpression": "#s = :expected_status",
                    "ExpressionAttributeNames": {"#s": "status"},
                    "ExpressionAttributeValues": {
                        ":new_status": {"S": "FULFILLED"},
                        ":expected_status": {"S": "RESERVED"},
                    },
                }
            },
            {
                "Delete": {
                    "TableName": table_name,
                    "Key": {"pk": {"S": reservation_key}},
                    "ConditionExpression": "attribute_exists(pk)",
                }
            },
        ]
    )

    # Step 4: the final state is consistent across all three items.
    stock_after = ddb.get_item(TableName=table_name, Key={"pk": {"S": stock_key}}, ConsistentRead=True)
    expected_qty = str(initial_qty - reserve_qty)
    assert stock_after["Item"]["quantity"]["N"] == expected_qty, (
        f"expected stock quantity {expected_qty!r} after settlement, saw {stock_after['Item']!r}"
    )

    order_after = ddb.get_item(TableName=table_name, Key={"pk": {"S": order_key}}, ConsistentRead=True)
    assert order_after["Item"]["status"]["S"] == "FULFILLED", (
        f"expected order status 'FULFILLED' after settlement, saw {order_after['Item']!r}"
    )

    reservation_after = ddb.get_item(
        TableName=table_name, Key={"pk": {"S": reservation_key}}, ConsistentRead=True
    )
    assert "Item" not in reservation_after, f"reservation hold was not released: {reservation_after!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
