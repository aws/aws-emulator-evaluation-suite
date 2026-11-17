"""transact-write-items-condition-check-contains-set-cancels-with-all-old-item."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-condition-check-contains-set-cancels-with-all-old-item"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_CCF_CODE = "ConditionalCheckFailed"
_CCF_MSG = "The conditional request failed"
_CANCELED = "TransactionCanceledException"
_CANCELED_MSG = ("Transaction cancelled, please refer cancellation reasons for specific "
                 "reasons [ConditionalCheckFailed, None]")


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise
    return run_undo


def _wait_active(ddb, table, timeout_s=120.0) -> None:
    """Poll DescribeTable every 2 s until the table is ACTIVE."""
    deadline = time.monotonic() + timeout_s
    while True:
        status = ddb.describe_table(TableName=table)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"table {table} not ACTIVE within {timeout_s:.0f}s; last status {status!r}")
        time.sleep(2)


def _expect_canceled(fn):
    """Call fn() and return its ClientError's response; an accepted call fails the check."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected the transaction to be cancelled, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes",
      "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems ConditionCheck with contains(SS, :v) false, and
    ReturnValuesOnConditionCheckFailure=ALL_OLD, cancels carrying the complete conflicting item.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-ddb-cc-contains-")
    ddb.create_table(
        TableName=table,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(_teardown(lambda: ddb.delete_table(TableName=table), "ResourceNotFoundException"))
    _wait_active(ddb, table)

    holder_key = {"pk": {"S": "holder"}}
    holder = {**holder_key, "roles": {"SS": ["admin", "viewer"]}}
    ddb.put_item(TableName=table, Item=holder)

    companion = {"pk": {"S": "companion"}}
    resp = _expect_canceled(lambda: ddb.transact_write_items(TransactItems=[
        {"ConditionCheck": {
            "TableName": table, "Key": holder_key,
            "ConditionExpression": "contains(#r, :v)",
            "ExpressionAttributeNames": {"#r": "roles"},
            "ExpressionAttributeValues": {":v": {"S": "owner"}},
            "ReturnValuesOnConditionCheckFailure": "ALL_OLD",
        }},
        {"Put": {"TableName": table, "Item": companion}},
    ]))
    assert resp["Error"]["Code"] == _CANCELED, f"got {resp['Error']['Code']!r}"
    assert resp["Error"].get("Message") == _CANCELED_MSG, f"got message {resp['Error'].get('Message')!r}"
    reasons = resp["CancellationReasons"]
    assert len(reasons) == 2, f"expected 2 cancellation reasons, got {reasons!r}"
    failed, ok = reasons[0], reasons[1]
    assert failed["Code"] == _CCF_CODE, f"got {failed!r}"
    assert failed.get("Message") == _CCF_MSG, f"got {failed!r}"
    assert failed.get("Item") == holder, f"ALL_OLD must return the complete conflicting item, got {failed.get('Item')!r}"
    assert ok["Code"] == "None", f"the non-failing member must report Code 'None', got {ok!r}"
    assert "Item" not in ok, f"the non-failing member must not carry an Item, got {ok!r}"

    got = ddb.get_item(TableName=table, Key=companion, ConsistentRead=True).get("Item")
    assert got is None, f"the cancelled transaction must not have created {companion}, got {got!r}"
    still = ddb.get_item(TableName=table, Key=holder_key, ConsistentRead=True)["Item"]
    assert still == holder, f"the holder item must be unchanged by the cancelled transaction, got {still!r}"

    # --- control: the same shape with a holding contains() condition commits both members ---
    ddb.transact_write_items(TransactItems=[
        {"ConditionCheck": {
            "TableName": table, "Key": holder_key,
            "ConditionExpression": "contains(#r, :v)",
            "ExpressionAttributeNames": {"#r": "roles"},
            "ExpressionAttributeValues": {":v": {"S": "admin"}},
            "ReturnValuesOnConditionCheckFailure": "ALL_OLD",
        }},
        {"Put": {"TableName": table, "Item": companion}},
    ])
    got = ddb.get_item(TableName=table, Key=companion, ConsistentRead=True).get("Item")
    assert got == companion, f"a holding contains() ConditionCheck must let the companion Put commit, got {got!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
