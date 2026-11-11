"""transact-write-items-delete-with-failed-condition-cancels-other-deletes-too."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-delete-with-failed-condition-cancels-other-deletes-too"
GROUP = "transactions"
SERVICES = ["dynamodb"]
_TX_CANCELLED = (
    "TransactionCanceledException",
    "Transaction cancelled, please refer cancellation reasons for specific reasons "
    "[None, ConditionalCheckFailed, None]",
)


def _expect_error(fn, code: str, message: str) -> None:
    """Call ``fn``, which must raise a ClientError with exactly this (code, message)."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected a refusal {(code, message)!r}, the call succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """One Delete's failed ConditionExpression cancels a TransactWriteItems entirely: the other
    Deletes in the same transaction do not apply, even though they carry no condition of their own."""
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    # Positive control: an unconditioned transaction of several distinct Deletes all apply.
    for key in ("tx-del-ctl-a", "tx-del-ctl-b"):
        ddb.put_item(TableName=table, Item={"pk": {"S": key}})
    ddb.transact_write_items(TransactItems=[
        {"Delete": {"TableName": table, "Key": {"pk": {"S": "tx-del-ctl-a"}}}},
        {"Delete": {"TableName": table, "Key": {"pk": {"S": "tx-del-ctl-b"}}}},
    ])
    for key in ("tx-del-ctl-a", "tx-del-ctl-b"):
        assert ddb.get_item(TableName=table, Key={"pk": {"S": key}},
                            ConsistentRead=True).get("Item") is None, (
            f"control: an unconditioned transactional Delete of {key!r} must have applied")

    # The negative: three items, the middle Delete's condition fails on an existing item.
    for key in ("tx-del-a", "tx-del-b", "tx-del-c"):
        ddb.put_item(TableName=table, Item={"pk": {"S": key}})

    def _transact_delete_three():
        return ddb.transact_write_items(TransactItems=[
            {"Delete": {"TableName": table, "Key": {"pk": {"S": "tx-del-a"}}}},
            {"Delete": {"TableName": table, "Key": {"pk": {"S": "tx-del-b"}},
                       "ConditionExpression": "attribute_not_exists(pk)"}},
            {"Delete": {"TableName": table, "Key": {"pk": {"S": "tx-del-c"}}}},
        ])
    _expect_error(_transact_delete_three, *_TX_CANCELLED)

    for key in ("tx-del-a", "tx-del-b", "tx-del-c"):
        got = ddb.get_item(TableName=table, Key={"pk": {"S": key}}, ConsistentRead=True).get("Item")
        assert got == {"pk": {"S": key}}, (
            f"the cancelled transaction must leave {key!r} untouched, got {got!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
