"""e2e-order-fulfillment-concurrent-stock-contention."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "e2e-order-fulfillment-concurrent-stock-contention"
GROUP = "e2e"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Two parallel conditional TransactWriteItems settlements against one unit of stock leave
    exactly one order FULFILLED and stock at 0; the loser gets TransactionCanceledException and
    its order stays RESERVED with its reservation HELD (all-or-nothing under contention)."""
    from botocore.exceptions import ClientError

    ddb = ctx.client("dynamodb")
    table_name = ctx.unique_name("sim2real-behav-fulfill-race-")
    ddb.create_table(
        TableName=table_name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": "e2e-order-fulfillment-concurrent-stock-contention"}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table_name))
    ddb.get_waiter("table_exists").wait(TableName=table_name, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    stock_key = "STOCK#sku-scarce"
    order_keys = ["ORDER#A", "ORDER#B"]
    reservation_keys = {"ORDER#A": "RESERVATION#A", "ORDER#B": "RESERVATION#B"}

    ddb.put_item(TableName=table_name, Item={"pk": {"S": stock_key}, "quantity": {"N": "1"}})
    for order_key in order_keys:
        ddb.put_item(
            TableName=table_name,
            Item={"pk": {"S": order_key}, "status": {"S": "PENDING"}, "sku": {"S": stock_key}},
        )
        reservation_key = reservation_keys[order_key]
        ddb.put_item(
            TableName=table_name,
            Item={
                "pk": {"S": reservation_key},
                "order": {"S": order_key},
                "qty": {"N": "1"},
                "status": {"S": "HELD"},
            },
            ConditionExpression="attribute_not_exists(pk)",
        )
        ddb.update_item(
            TableName=table_name,
            Key={"pk": {"S": order_key}},
            UpdateExpression="SET #s = :new_status",
            ConditionExpression="#s = :expected_status",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":new_status": {"S": "RESERVED"},
                ":expected_status": {"S": "PENDING"},
            },
        )

    def _settle(order_key: str):
        reservation_key = reservation_keys[order_key]
        try:
            ddb.transact_write_items(
                TransactItems=[
                    {
                        "Update": {
                            "TableName": table_name,
                            "Key": {"pk": {"S": stock_key}},
                            "UpdateExpression": "SET quantity = quantity - :qty",
                            "ConditionExpression": "quantity >= :qty",
                            "ExpressionAttributeValues": {":qty": {"N": "1"}},
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
            return order_key, None
        except ClientError as err:
            return order_key, err.response

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_settle, order_keys))

    winners = [order_key for order_key, error in results if error is None]
    losers = {order_key: error for order_key, error in results if error is not None}

    assert len(winners) == 1, f"expected exactly one winner, got {winners!r} (results={results!r})"
    assert len(losers) == 1, f"expected exactly one loser, got {losers!r}"
    (loser_key, loser_error) = next(iter(losers.items()))
    loser_code = loser_error["Error"]["Code"]
    loser_message = loser_error["Error"].get("Message")
    assert loser_code == "TransactionCanceledException", (
        f"expected TransactionCanceledException for the loser, saw {loser_code!r}"
    )
    # The loser lost either on the stock condition (ConditionalCheckFailed) or by overlapping the
    # winner (TransactionConflict), on the stock update, the transaction's first action; the other
    # two actions carry no reason. The message lists those reasons in action order.
    reasons = [r.get("Code") for r in loser_error.get("CancellationReasons", [])]
    assert reasons in (
        ["ConditionalCheckFailed", "None", "None"],
        ["TransactionConflict", "None", "None"],
    ), f"expected the loser cancelled on the stock update alone, got reasons {reasons!r}"
    expected_message = (
        "Transaction cancelled, please refer cancellation reasons for specific reasons "
        f"[{', '.join(reasons)}]"
    )
    assert loser_message == expected_message, (
        f"expected the loser's message {expected_message!r}, got {loser_message!r}"
    )

    stock_after = ddb.get_item(TableName=table_name, Key={"pk": {"S": stock_key}}, ConsistentRead=True)
    assert stock_after["Item"]["quantity"]["N"] == "0", (
        f"expected stock to be depleted to 0 after exactly one settlement, "
        f"got {stock_after['Item']['quantity']['N']!r}"
    )

    winner_key = winners[0]
    winner_order = ddb.get_item(TableName=table_name, Key={"pk": {"S": winner_key}}, ConsistentRead=True)
    assert winner_order["Item"]["status"]["S"] == "FULFILLED", (
        f"expected winner order {winner_key!r} to be FULFILLED, "
        f"got {winner_order['Item']['status']['S']!r}"
    )
    winner_reservation = ddb.get_item(
        TableName=table_name, Key={"pk": {"S": reservation_keys[winner_key]}}, ConsistentRead=True
    )
    assert "Item" not in winner_reservation, "winner's reservation hold should have been released"

    # The loser's TransactWriteItems was rejected wholesale: its order status and reservation
    # hold must be exactly as they were before the race (untouched by the failed transaction).
    loser_order = ddb.get_item(TableName=table_name, Key={"pk": {"S": loser_key}}, ConsistentRead=True)
    assert loser_order["Item"]["status"]["S"] == "RESERVED", (
        f"expected loser order {loser_key!r} to be untouched at RESERVED, "
        f"got {loser_order['Item']['status']['S']!r}"
    )
    loser_reservation = ddb.get_item(
        TableName=table_name, Key={"pk": {"S": reservation_keys[loser_key]}}, ConsistentRead=True
    )
    assert loser_reservation["Item"]["status"]["S"] == "HELD", (
        f"expected loser's reservation hold to remain HELD, "
        f"got {loser_reservation['Item']['status']['S']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
