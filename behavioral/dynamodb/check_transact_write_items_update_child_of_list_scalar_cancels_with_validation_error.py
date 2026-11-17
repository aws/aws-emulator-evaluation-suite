"""transact-write-items-update-child-of-list-scalar-cancels-with-validation-error."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-update-child-of-list-scalar-cancels-with-validation-error"
GROUP = "transactions"
SERVICES = ["dynamodb"]

_TABLE_ACTIVE_BUDGET_S = 120.0
_TEARDOWN_WAIT_S = 120.0
_ERR_CANCELED = "TransactionCanceledException"
_CANCELED_PREFIX = "Transaction cancelled, please refer cancellation reasons for specific reasons "
_PATH_INVALID_MSG = "The document path provided in the update expression is invalid for update"


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
    """A TransactWriteItems Update setting a child path of a list element that holds a scalar
    cancels that member with ValidationError, alongside another member's own failure reason.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_TransactWriteItems.html
    """
    ddb = ctx.client("dynamodb")
    table = _create_table(ctx, ddb)

    locked_key = {"pk": {"S": "locked"}}
    ddb.put_item(TableName=table, Item={**locked_key, "status": {"S": "LOCKED"}})

    doc_key = {"pk": {"S": "doc"}}
    doc_item = {
        **doc_key,
        "items": {"L": [{"M": {"child": {"N": "1"}}}, {"S": "not-a-map"}]},
    }
    ddb.put_item(TableName=table, Item=doc_item)

    cc_fails = {"ConditionCheck": {
        "TableName": table,
        "Key": locked_key,
        "ConditionExpression": "#s = :expected",
        "ExpressionAttributeNames": {"#s": "status"},
        "ExpressionAttributeValues": {":expected": {"S": "UNLOCKED"}},
    }}
    # items[1] is a String, not a Map; setting a child path through it is invalid.
    update_scalar_child = {"Update": {
        "TableName": table,
        "Key": doc_key,
        "UpdateExpression": "SET #i[1].#c = :v",
        "ExpressionAttributeNames": {"#i": "items", "#c": "child"},
        "ExpressionAttributeValues": {":v": {"S": "x"}},
    }}

    err = _canceled(lambda: ddb.transact_write_items(TransactItems=[cc_fails, update_scalar_child]))
    assert err["Error"]["Code"] == _ERR_CANCELED, f"expected {_ERR_CANCELED}, got {err['Error']!r}"
    expected_message = _CANCELED_PREFIX + "[ConditionalCheckFailed, ValidationError]"
    assert err["Error"].get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err['Error'].get('Message')!r}"
    )
    reasons = err.get("CancellationReasons")
    assert reasons is not None and len(reasons) == 2, f"expected 2 cancellation reasons, got {reasons}"
    cc_reason, update_reason = reasons
    assert cc_reason["Code"] == "ConditionalCheckFailed", f"member 0 should be ConditionalCheckFailed, got {cc_reason}"
    assert update_reason["Code"] == "ValidationError", f"member 1 should be ValidationError, got {update_reason}"
    assert update_reason.get("Message") == _PATH_INVALID_MSG, (
        f"a child path through a scalar list element must carry {_PATH_INVALID_MSG!r}, "
        f"got {update_reason.get('Message')!r}"
    )

    unchanged = ddb.get_item(TableName=table, Key=doc_key, ConsistentRead=True)["Item"]
    assert unchanged == doc_item, f"the canceled Update must leave the document unchanged, got {unchanged}"

    # Positive control: the same shape, targeting items[0], which IS a Map, commits.
    ddb.transact_write_items(TransactItems=[
        {"ConditionCheck": {
            "TableName": table,
            "Key": locked_key,
            "ConditionExpression": "#s = :expected",
            "ExpressionAttributeNames": {"#s": "status"},
            "ExpressionAttributeValues": {":expected": {"S": "LOCKED"}},
        }},
        {"Update": {
            "TableName": table,
            "Key": doc_key,
            "UpdateExpression": "SET #i[0].#c = :v",
            "ExpressionAttributeNames": {"#i": "items", "#c": "child"},
            "ExpressionAttributeValues": {":v": {"N": "2"}},
        }},
    ])
    committed = ddb.get_item(TableName=table, Key=doc_key, ConsistentRead=True)["Item"]
    expected_committed = {
        **doc_key,
        "items": {"L": [{"M": {"child": {"N": "2"}}}, {"S": "not-a-map"}]},
    }
    assert committed == expected_committed, (
        f"a child path through a Map list element must commit, got {committed}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
