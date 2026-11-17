"""transact-write-items-update-runtime-arithmetic-error-reports-validation-error-reason."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-update-runtime-arithmetic-error-reports-validation-error-reason"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_TABLE_ACTIVE_BUDGET_S = 120.0
_TEARDOWN_WAIT_S = 120.0
_ERR_CANCELED = "TransactionCanceledException"
_CANCELED_PREFIX = "Transaction cancelled, please refer cancellation reasons for specific reasons "
_TYPE_MISMATCH_MSG = "An operand in the update expression has an incorrect data type"


def _canceled(fn):
    """The err response of the ClientError ``fn`` raises; RAISES if it unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response
    raise AssertionError(f"expected the transaction to be canceled, but it succeeded: {result!r}")


def _delete_table_when_possible(ddb, table_name):
    deadline = time.monotonic() + _TEARDOWN_WAIT_S
    while True:
        try:
            ddb.delete_table(TableName=table_name)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ResourceNotFoundException":
                return
            if code == "ResourceInUseException" and time.monotonic() < deadline:
                time.sleep(5.0)
                continue
            raise


def _create_table(ctx, ddb):
    name = ctx.unique_name("sim2real-behav-ddb-")
    ddb.create_table(
        TableName=name,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_table_when_possible(ddb, name))
    deadline = time.monotonic() + _TABLE_ACTIVE_BUDGET_S
    status = None
    while time.monotonic() < deadline:
        status = ddb.describe_table(TableName=name)["Table"]["TableStatus"]
        if status == "ACTIVE":
            return name
        time.sleep(2.0)
    raise AssertionError(f"table {name!r} not ACTIVE within {_TABLE_ACTIVE_BUDGET_S}s: {status!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems member's runtime arithmetic type error reports ValidationError on its
    own CancellationReasons slot, positionally aligned with the request regardless of order.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)

    locked_key = {"pk": {"S": "locked"}}
    ddb.put_item(TableName=table, Item={**locked_key, "status": {"S": "LOCKED"}})
    counter_key = {"pk": {"S": "counter"}}
    # ``n`` is stored as a String; "+" needs the stored value's type read at runtime to detect
    # the mismatch, unlike a request-literal type mismatch, which DynamoDB rejects up front.
    counter_item = {**counter_key, "n": {"S": "not-a-number"}}
    ddb.put_item(TableName=table, Item=counter_item)

    cc_member = {"ConditionCheck": {
        "TableName": table,
        "Key": locked_key,
        "ConditionExpression": "#s = :expected",
        "ExpressionAttributeNames": {"#s": "status"},
        "ExpressionAttributeValues": {":expected": {"S": "UNLOCKED"}},
    }}
    bad_update_member = {"Update": {
        "TableName": table,
        "Key": counter_key,
        "UpdateExpression": "SET n = n + :one",
        "ExpressionAttributeValues": {":one": {"N": "1"}},
    }}
    harmless_put_a_key = {"pk": {"S": "harmless-a"}}
    harmless_put_a = {"Put": {"TableName": table, "Item": harmless_put_a_key}}

    # Order 1: ConditionCheck, Update, Put — the condition fails first; the runtime arithmetic
    # error on the Update still reports its own reason; the untouched Put reports "None".
    err = _canceled(lambda: ddb.transact_write_items(
        TransactItems=[cc_member, bad_update_member, harmless_put_a]
    ))
    assert err["Error"]["Code"] == _ERR_CANCELED, f"expected {_ERR_CANCELED}, got {err['Error']!r}"
    expected_message = _CANCELED_PREFIX + "[ConditionalCheckFailed, ValidationError, None]"
    assert err["Error"].get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err['Error'].get('Message')!r}"
    )
    reasons = err.get("CancellationReasons")
    assert reasons is not None and len(reasons) == 3, f"expected 3 cancellation reasons, got {reasons}"
    cc_reason, update_reason, put_reason = reasons
    assert cc_reason["Code"] == "ConditionalCheckFailed", f"member 0 should be ConditionalCheckFailed, got {cc_reason}"
    assert update_reason["Code"] == "ValidationError", f"member 1 should be ValidationError, got {update_reason}"
    assert update_reason.get("Message") == _TYPE_MISMATCH_MSG, (
        f"the runtime arithmetic error must carry {_TYPE_MISMATCH_MSG!r}, got {update_reason.get('Message')!r}"
    )
    assert put_reason["Code"] == "None", f"member 2 should report Code 'None', got {put_reason}"
    assert "Item" not in put_reason, f"the non-failing member must not carry an Item, got {put_reason}"

    unchanged = ddb.get_item(TableName=table, Key=counter_key, ConsistentRead=True)["Item"]
    assert unchanged == counter_item, f"the canceled Update must leave the counter unchanged, got {unchanged}"
    assert "Item" not in ddb.get_item(TableName=table, Key=harmless_put_a_key, ConsistentRead=True), (
        "the canceled transaction must not have created the untouched Put's item"
    )

    # Order 2: Delete, Update, ConditionCheck. CancellationReasons stay positionally aligned with
    # the request order, not with evaluation or failure order; the Delete member, which would have
    # succeeded on its own, reports "None" even though the whole transaction is canceled.
    deletable_key = {"pk": {"S": "deletable"}}
    deletable_item = {**deletable_key, "v": {"S": "x"}}
    ddb.put_item(TableName=table, Item=deletable_item)
    err = _canceled(lambda: ddb.transact_write_items(TransactItems=[
        {"Delete": {"TableName": table, "Key": deletable_key}},
        bad_update_member,
        cc_member,
    ]))
    assert err["Error"]["Code"] == _ERR_CANCELED, f"expected {_ERR_CANCELED}, got {err['Error']!r}"
    expected_message = _CANCELED_PREFIX + "[None, ValidationError, ConditionalCheckFailed]"
    assert err["Error"].get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err['Error'].get('Message')!r}"
    )
    reasons = err.get("CancellationReasons")
    assert reasons is not None and len(reasons) == 3, f"expected 3 cancellation reasons, got {reasons}"
    delete_reason, update_reason, cc_reason = reasons
    assert delete_reason["Code"] == "None", f"member 0 should report Code 'None', got {delete_reason}"
    assert update_reason["Code"] == "ValidationError", f"member 1 should be ValidationError, got {update_reason}"
    assert update_reason.get("Message") == _TYPE_MISMATCH_MSG, (
        f"the runtime arithmetic error must carry {_TYPE_MISMATCH_MSG!r}, got {update_reason.get('Message')!r}"
    )
    assert cc_reason["Code"] == "ConditionalCheckFailed", f"member 2 should be ConditionalCheckFailed, got {cc_reason}"

    unchanged = ddb.get_item(TableName=table, Key=counter_key, ConsistentRead=True)["Item"]
    assert unchanged == counter_item, f"the second canceled Update must still leave the counter unchanged, got {unchanged}"
    still_there = ddb.get_item(TableName=table, Key=deletable_key, ConsistentRead=True)["Item"]
    assert still_there == deletable_item, (
        f"the canceled transaction must not have applied the Delete member, got {still_there}"
    )

    # Positive control: the same three member kinds, all satisfiable, commit together. A
    # separate numeric-typed item stands in for the Update member, since the runtime-mismatched
    # counter above never holds a usable numeric value to add to.
    numeric_key = {"pk": {"S": "numeric"}}
    ddb.put_item(TableName=table, Item={**numeric_key, "n": {"N": "5"}})
    harmless_put_c_key = {"pk": {"S": "harmless-c"}}
    ddb.transact_write_items(TransactItems=[
        {"Put": {"TableName": table, "Item": harmless_put_c_key}},
        {"Update": {
            "TableName": table,
            "Key": numeric_key,
            "UpdateExpression": "SET n = n + :one",
            "ExpressionAttributeValues": {":one": {"N": "1"}},
        }},
        {"ConditionCheck": {
            "TableName": table,
            "Key": locked_key,
            "ConditionExpression": "#s = :expected",
            "ExpressionAttributeNames": {"#s": "status"},
            "ExpressionAttributeValues": {":expected": {"S": "LOCKED"}},
        }},
    ])
    committed = ddb.get_item(TableName=table, Key=numeric_key, ConsistentRead=True)["Item"]
    assert committed == {**numeric_key, "n": {"N": "6"}}, f"a committed transaction must apply the Update, got {committed}"
    assert ddb.get_item(TableName=table, Key=harmless_put_c_key, ConsistentRead=True)["Item"] == harmless_put_c_key, (
        "a committed transaction must apply the sibling Put"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
