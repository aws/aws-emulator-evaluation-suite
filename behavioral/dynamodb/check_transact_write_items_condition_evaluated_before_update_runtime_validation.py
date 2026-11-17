"""transact-write-items-condition-evaluated-before-update-runtime-validation."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-condition-evaluated-before-update-runtime-validation"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_TABLE_ACTIVE_BUDGET_S = 120.0
_TEARDOWN_WAIT_S = 120.0
_ERR_CANCELED = "TransactionCanceledException"
_CANCELED_PREFIX = "Transaction cancelled, please refer cancellation reasons for specific reasons "
_COND_FAILED_MSG = "The conditional request failed"
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


def _bad_update(table, key, *, condition_expected: str, return_old: bool) -> dict:
    member = {
        "TableName": table,
        "Key": key,
        "UpdateExpression": "SET n = n + :one",
        "ConditionExpression": "#s = :expected",
        "ExpressionAttributeNames": {"#s": "status"},
        "ExpressionAttributeValues": {":one": {"N": "1"}, ":expected": {"S": condition_expected}},
    }
    if return_old:
        member["ReturnValuesOnConditionCheckFailure"] = "ALL_OLD"
    return {"Update": member}


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems Update's ConditionExpression is evaluated before its UpdateExpression:
    a false condition reports only ConditionalCheckFailed and never evaluates the arithmetic; a
    true condition lets the runtime arithmetic error surface as its own ValidationError reason.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)

    key = {"pk": {"S": "counter"}}
    # ``n`` is stored as a String; "+" needs the stored value's type read at runtime to detect
    # the mismatch, unlike a request-literal type mismatch, which DynamoDB rejects up front.
    original = {**key, "n": {"S": "not-a-number"}, "status": {"S": "ON"}}
    ddb.put_item(TableName=table, Item=original)

    # (a) False condition + invalid arithmetic, alone: only ConditionalCheckFailed is reported,
    # and ReturnValuesOnConditionCheckFailure returns the complete conflicting item.
    err = _canceled(lambda: ddb.transact_write_items(TransactItems=[
        _bad_update(table, key, condition_expected="OFF", return_old=True),
    ]))
    assert err["Error"]["Code"] == _ERR_CANCELED, f"expected {_ERR_CANCELED}, got {err['Error']!r}"
    expected_message = _CANCELED_PREFIX + "[ConditionalCheckFailed]"
    assert err["Error"].get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err['Error'].get('Message')!r}"
    )
    reasons = err.get("CancellationReasons")
    assert reasons is not None and len(reasons) == 1, f"expected 1 cancellation reason, got {reasons}"
    assert reasons[0]["Code"] == "ConditionalCheckFailed", (
        f"a false condition must report ConditionalCheckFailed, not the arithmetic error, got {reasons[0]}"
    )
    assert reasons[0].get("Message") == _COND_FAILED_MSG, (
        f"expected {_COND_FAILED_MSG!r}, got {reasons[0].get('Message')!r}"
    )
    assert reasons[0].get("Item") == original, (
        f"ReturnValuesOnConditionCheckFailure=ALL_OLD must return the complete item {original}, "
        f"got {reasons[0].get('Item')}"
    )
    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged == original, f"the canceled Update must leave the item unchanged, got {unchanged}"

    # (b) True condition + invalid arithmetic: the condition passes, so the runtime arithmetic
    # error is reached and reported as the member's own ValidationError reason.
    err = _canceled(lambda: ddb.transact_write_items(TransactItems=[
        _bad_update(table, key, condition_expected="ON", return_old=False),
    ]))
    assert err["Error"]["Code"] == _ERR_CANCELED, f"expected {_ERR_CANCELED}, got {err['Error']!r}"
    expected_message = _CANCELED_PREFIX + "[ValidationError]"
    assert err["Error"].get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err['Error'].get('Message')!r}"
    )
    reasons = err.get("CancellationReasons")
    assert reasons is not None and len(reasons) == 1, f"expected 1 cancellation reason, got {reasons}"
    assert reasons[0]["Code"] == "ValidationError", (
        f"a true condition must let the arithmetic error surface as ValidationError, got {reasons[0]}"
    )
    assert reasons[0].get("Message") == _TYPE_MISMATCH_MSG, (
        f"expected {_TYPE_MISMATCH_MSG!r}, got {reasons[0].get('Message')!r}"
    )
    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged == original, f"the canceled Update must still leave the item unchanged, got {unchanged}"

    # (c) The same false-condition member, alongside an unrelated sibling Put: the condition
    # failure still suppresses the arithmetic error, and the sibling reports "None".
    sibling_key = {"pk": {"S": "sibling"}}
    err = _canceled(lambda: ddb.transact_write_items(TransactItems=[
        _bad_update(table, key, condition_expected="OFF", return_old=False),
        {"Put": {"TableName": table, "Item": sibling_key}},
    ]))
    assert err["Error"]["Code"] == _ERR_CANCELED, f"expected {_ERR_CANCELED}, got {err['Error']!r}"
    expected_message = _CANCELED_PREFIX + "[ConditionalCheckFailed, None]"
    assert err["Error"].get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err['Error'].get('Message')!r}"
    )
    reasons = err.get("CancellationReasons")
    assert reasons is not None and len(reasons) == 2, f"expected 2 cancellation reasons, got {reasons}"
    update_reason, put_reason = reasons
    assert update_reason["Code"] == "ConditionalCheckFailed", (
        f"the false condition must still suppress the arithmetic error with a sibling present, got {update_reason}"
    )
    assert put_reason["Code"] == "None", f"the sibling Put must report Code 'None', got {put_reason}"
    unchanged = ddb.get_item(TableName=table, Key=key, ConsistentRead=True)["Item"]
    assert unchanged == original, f"the canceled Update must still leave the item unchanged, got {unchanged}"
    assert "Item" not in ddb.get_item(TableName=table, Key=sibling_key, ConsistentRead=True), (
        "the canceled transaction must not have created the sibling item"
    )

    # Positive control: a true condition with valid arithmetic commits. A separate numeric-typed
    # item stands in for the Update member, since ``counter`` never holds a usable numeric value.
    numeric_key = {"pk": {"S": "numeric"}}
    ddb.put_item(TableName=table, Item={**numeric_key, "n": {"N": "5"}, "status": {"S": "ON"}})
    ddb.transact_write_items(TransactItems=[{"Update": {
        "TableName": table,
        "Key": numeric_key,
        "UpdateExpression": "SET n = n + :one",
        "ConditionExpression": "#s = :expected",
        "ExpressionAttributeNames": {"#s": "status"},
        "ExpressionAttributeValues": {":one": {"N": "1"}, ":expected": {"S": "ON"}},
    }}])
    committed = ddb.get_item(TableName=table, Key=numeric_key, ConsistentRead=True)["Item"]
    assert committed == {**numeric_key, "n": {"N": "6"}, "status": {"S": "ON"}}, (
        f"a satisfiable condition with valid arithmetic must commit, got {committed}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
