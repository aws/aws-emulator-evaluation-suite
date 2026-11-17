"""transact-write-items-delete-operand-type-and-condition-check-reasons-track-item-identity."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "transact-write-items-delete-operand-type-and-condition-check-reasons-track-item-identity"
GROUP = "transactions"
SERVICES = ["dynamodb"]
ERR_CANCELLED = "TransactionCanceledException"
_TYPE_MISMATCH = "An operand in the update expression has an incorrect data type"
_CCF_MESSAGE = "The conditional request failed"


def _cancelled(fn):
    """The ClientError raised by ``fn()``; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        return exc
    raise AssertionError(f"expected {ERR_CANCELLED}, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A TransactWriteItems DELETE whose set operand has the wrong element type cancels with a
    per-item ValidationError reason, not a top-level error, and its reason tracks the item across
    a reordering of TransactItems exactly as a ConditionalCheckFailed reason beside it does.
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-ddbtxn-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    tagged_key = {"pk": {"S": "tagged"}}
    missing_key = {"pk": {"S": "missing"}}
    ddb.put_item(TableName=t, Item={**tagged_key, "tags": {"SS": ["red", "blue"]}})
    # "missing" is never put, so its ConditionCheck fails every time below.

    def delete_wrong_type_action():
        return {
            "Update": {
                "TableName": t,
                "Key": tagged_key,
                "UpdateExpression": "DELETE tags :v",
                "ExpressionAttributeValues": {":v": {"NS": ["1", "2"]}},
            }
        }

    def condition_check_action():
        return {
            "ConditionCheck": {
                "TableName": t,
                "Key": missing_key,
                "ConditionExpression": "attribute_exists(pk)",
            }
        }

    exc1 = _cancelled(lambda: ddb.transact_write_items(
        TransactItems=[delete_wrong_type_action(), condition_check_action()]
    ))
    err1 = exc1.response["Error"]
    assert err1["Code"] == ERR_CANCELLED, f"expected {ERR_CANCELLED}, got {err1['Code']!r}"
    reasons1 = exc1.response.get("CancellationReasons") or []
    assert len(reasons1) == 2, f"expected 2 positionally-aligned cancellation reasons, got {reasons1!r}"
    assert reasons1[0]["Code"] == "ValidationError", (
        f"expected the wrong-typed DELETE (index 0) to report ValidationError, got {reasons1[0]!r}"
    )
    validation_message = reasons1[0].get("Message")
    assert validation_message == _TYPE_MISMATCH, (
        f"expected the ValidationError reason message {_TYPE_MISMATCH!r}, got {validation_message!r}"
    )
    assert reasons1[1]["Code"] == "ConditionalCheckFailed", (
        f"expected the failed ConditionCheck (index 1) to report ConditionalCheckFailed, got {reasons1[1]!r}"
    )
    ccf_message = reasons1[1].get("Message")
    assert ccf_message == _CCF_MESSAGE, (
        f"expected the ConditionalCheckFailed reason message {_CCF_MESSAGE!r}, got {ccf_message!r}"
    )
    expected_top_message1 = (
        "Transaction cancelled, please refer cancellation reasons for specific reasons "
        "[ValidationError, ConditionalCheckFailed]"
    )
    assert err1.get("Message") == expected_top_message1, (
        f"expected top-level message {expected_top_message1!r}, got {err1.get('Message')!r}"
    )

    # Swap the two members' positions: the reason codes and messages follow their item, not
    # their slot.
    exc2 = _cancelled(lambda: ddb.transact_write_items(
        TransactItems=[condition_check_action(), delete_wrong_type_action()]
    ))
    err2 = exc2.response["Error"]
    assert err2["Code"] == ERR_CANCELLED, f"expected {ERR_CANCELLED}, got {err2['Code']!r}"
    reasons2 = exc2.response.get("CancellationReasons") or []
    assert len(reasons2) == 2, f"expected 2 positionally-aligned cancellation reasons, got {reasons2!r}"
    assert reasons2[0]["Code"] == "ConditionalCheckFailed", (
        f"expected the ConditionCheck, now at index 0, to report ConditionalCheckFailed, got {reasons2[0]!r}"
    )
    assert reasons2[0].get("Message") == ccf_message, (
        f"ConditionalCheckFailed message changed with position: {reasons2[0].get('Message')!r} vs {ccf_message!r}"
    )
    assert reasons2[1]["Code"] == "ValidationError", (
        f"expected the wrong-typed DELETE, now at index 1, to report ValidationError, got {reasons2[1]!r}"
    )
    assert reasons2[1].get("Message") == validation_message, (
        f"ValidationError message changed with position: {reasons2[1].get('Message')!r} vs {validation_message!r}"
    )
    expected_top_message2 = (
        "Transaction cancelled, please refer cancellation reasons for specific reasons "
        "[ConditionalCheckFailed, ValidationError]"
    )
    assert err2.get("Message") == expected_top_message2, (
        f"expected top-level message {expected_top_message2!r}, got {err2.get('Message')!r}"
    )

    # Neither cancelled attempt touched the item under test.
    unchanged = ddb.get_item(TableName=t, Key=tagged_key, ConsistentRead=True)["Item"]
    assert set(unchanged["tags"]["SS"]) == {"red", "blue"}, (
        f"both cancelled transactions must leave tags untouched, got {unchanged['tags']!r}"
    )

    # Positive control: fix both the operand type and the missing condition target, then the
    # identical shape of transaction commits.
    ddb.put_item(TableName=t, Item=missing_key)
    ddb.transact_write_items(TransactItems=[
        {
            "Update": {
                "TableName": t,
                "Key": tagged_key,
                "UpdateExpression": "DELETE tags :v",
                "ExpressionAttributeValues": {":v": {"SS": ["red"]}},
            }
        },
        {
            "ConditionCheck": {
                "TableName": t,
                "Key": missing_key,
                "ConditionExpression": "attribute_exists(pk)",
            }
        },
    ])
    shrunk = ddb.get_item(TableName=t, Key=tagged_key, ConsistentRead=True)["Item"]
    assert set(shrunk["tags"]["SS"]) == {"blue"}, (
        f"the positive-control DELETE must remove the named element, got {shrunk['tags']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
