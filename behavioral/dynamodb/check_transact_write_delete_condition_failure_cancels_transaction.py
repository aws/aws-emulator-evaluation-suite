"""transact-write-delete-condition-failure-cancels-transaction."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-delete-condition-failure-cancels-transaction"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_ERR_CANCELED = "TransactionCanceledException"
_COND_FAILED_MSG = "The conditional request failed"
_CANCELED_PREFIX = "Transaction cancelled, please refer cancellation reasons for specific reasons "


def _canceled(fn):
    """The err response of the ClientError ``fn`` raises; RAISES if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected the transaction to be canceled, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A Delete member's failed ConditionExpression cancels the whole TransactWriteItems call;
    the targeted item is not deleted and a sibling Put member in the same call does not commit.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": "transact-write-delete-condition-failure-cancels-transaction"}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    target = {"pk": {"S": "locked-record"}, "status": {"S": "LOCKED"}}
    ddb.put_item(TableName=table, Item=target)

    # The Delete member's condition requires status = UNLOCKED, which is false; the Put member
    # would otherwise succeed on its own.
    err = _canceled(lambda: ddb.transact_write_items(TransactItems=[
        {"Delete": {
            "TableName": table,
            "Key": {"pk": {"S": "locked-record"}},
            "ConditionExpression": "#s = :expected",
            "ExpressionAttributeNames": {"#s": "status"},
            "ExpressionAttributeValues": {":expected": {"S": "UNLOCKED"}},
            "ReturnValuesOnConditionCheckFailure": "ALL_OLD",
        }},
        {"Put": {
            "TableName": table,
            "Item": {"pk": {"S": "sibling-record"}, "status": {"S": "CREATED"}},
        }},
    ]))

    assert err["Error"]["Code"] == _ERR_CANCELED, (
        f"expected {_ERR_CANCELED}, got {err['Error'].get('Code')!r}"
    )
    expected_message = _CANCELED_PREFIX + "[ConditionalCheckFailed, None]"
    assert err["Error"].get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err['Error'].get('Message')!r}"
    )

    reasons = err.get("CancellationReasons")
    assert reasons is not None and len(reasons) == 2, (
        f"CancellationReasons must be positionally aligned with the 2 TransactItems, got {reasons}"
    )
    delete_reason, put_reason = reasons[0], reasons[1]
    assert delete_reason["Code"] == "ConditionalCheckFailed", (
        f"the Delete member must report ConditionalCheckFailed, got {delete_reason}"
    )
    assert delete_reason.get("Message") == _COND_FAILED_MSG, (
        f"the Delete member must carry {_COND_FAILED_MSG!r}, got {delete_reason.get('Message')!r}"
    )
    assert delete_reason.get("Item") == target, (
        f"ReturnValuesOnConditionCheckFailure=ALL_OLD must return the complete conflicting item "
        f"{target}, got {delete_reason.get('Item')}"
    )
    assert put_reason["Code"] == "None", f"the Put member must report Code 'None', got {put_reason}"
    assert "Item" not in put_reason, (
        f"the non-failing member must not carry an Item, got {put_reason.get('Item')}"
    )

    # Effect absent: the targeted item is still there, unchanged, and the sibling was never created.
    still = ddb.get_item(TableName=table, Key={"pk": {"S": "locked-record"}}, ConsistentRead=True)["Item"]
    assert still == target, f"the canceled Delete must leave the item unchanged, got {still}"
    assert "Item" not in ddb.get_item(
        TableName=table, Key={"pk": {"S": "sibling-record"}}, ConsistentRead=True
    ), "the canceled transaction must not have created the sibling item"

    # Positive control: the same shape, with a satisfiable condition, deletes the item and
    # commits the sibling Put.
    ddb.transact_write_items(TransactItems=[
        {"Delete": {
            "TableName": table,
            "Key": {"pk": {"S": "locked-record"}},
            "ConditionExpression": "#s = :expected",
            "ExpressionAttributeNames": {"#s": "status"},
            "ExpressionAttributeValues": {":expected": {"S": "LOCKED"}},
        }},
        {"Put": {
            "TableName": table,
            "Item": {"pk": {"S": "sibling-record"}, "status": {"S": "CREATED"}},
        }},
    ])
    assert "Item" not in ddb.get_item(
        TableName=table, Key={"pk": {"S": "locked-record"}}, ConsistentRead=True
    ), "a satisfiable condition must let the Delete remove the item"
    committed = ddb.get_item(
        TableName=table, Key={"pk": {"S": "sibling-record"}}, ConsistentRead=True
    )["Item"]
    assert committed == {"pk": {"S": "sibling-record"}, "status": {"S": "CREATED"}}, (
        f"a committed transaction must write the sibling Put, got {committed}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
