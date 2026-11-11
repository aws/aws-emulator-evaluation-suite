"""batch-execute-statement-condition-failure-returns-item-in-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-execute-statement-condition-failure-returns-item-in-error"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _stored(ddb, table, pk):
    return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchExecuteStatement reports a per-statement conditional-write failure as that slot's
    Error rather than aborting the batch, and with ReturnValuesOnConditionCheckFailure=ALL_OLD
    the Error carries the item's current value, absent without the opt-in.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_BatchExecuteStatement.html
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real-behav", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ok_item = {"pk": {"S": "ok"}, "val": {"S": "original-ok"}}
    stale_item = {"pk": {"S": "stale"}, "val": {"S": "current-stale"}}
    silent_item = {"pk": {"S": "silent"}, "val": {"S": "current-silent"}}
    ddb.put_item(TableName=t, Item=ok_item)
    ddb.put_item(TableName=t, Item=stale_item)
    ddb.put_item(TableName=t, Item=silent_item)

    resp = ddb.batch_execute_statement(Statements=[
        {
            "Statement": f'UPDATE "{t}" SET val = ? WHERE pk = ? AND val = ?',
            "Parameters": [{"S": "updated-ok"}, {"S": "ok"}, {"S": "original-ok"}],
        },
        {
            "Statement": f'UPDATE "{t}" SET val = ? WHERE pk = ? AND val = ?',
            "Parameters": [{"S": "clobbered"}, {"S": "stale"}, {"S": "WRONG-expected-value"}],
            "ReturnValuesOnConditionCheckFailure": "ALL_OLD",
        },
        {
            "Statement": f'UPDATE "{t}" SET val = ? WHERE pk = ? AND val = ?',
            "Parameters": [{"S": "clobbered"}, {"S": "silent"}, {"S": "WRONG-expected-value"}],
        },
    ])
    responses = resp["Responses"]
    assert len(responses) == 3, f"expected 3 per-statement responses, got {len(responses)}: {responses}"
    ok_slot, with_opt_in_slot, without_opt_in_slot = responses

    assert "Error" not in ok_slot, f"expected the matching-condition UPDATE to succeed, got {ok_slot!r}"
    assert _stored(ddb, t, "ok") == {"pk": {"S": "ok"}, "val": {"S": "updated-ok"}}, (
        f"the sibling's successful UPDATE must have applied, got {_stored(ddb, t, 'ok')!r}"
    )

    error = with_opt_in_slot.get("Error")
    assert error is not None, f"expected the failing UPDATE slot to carry a per-slot Error, got {with_opt_in_slot!r}"
    assert error.get("Code") == "ConditionalCheckFailed", (
        f"expected Error.Code 'ConditionalCheckFailed', got {error.get('Code')!r}"
    )
    assert error.get("Message") == "The conditional request failed", (
        f"expected AWS's exact message, got {error.get('Message')!r}"
    )
    assert error.get("Item") == stale_item, (
        f"ReturnValuesOnConditionCheckFailure=ALL_OLD must surface the complete current item in "
        f"Error.Item, got {error.get('Item')!r}"
    )
    unchanged = _stored(ddb, t, "stale")
    assert unchanged == stale_item, (
        f"a rejected conditional UPDATE in the batch must not modify the item, got {unchanged!r}"
    )

    silent_error = without_opt_in_slot.get("Error")
    assert silent_error is not None, (
        f"expected the second failing UPDATE slot to carry a per-slot Error too, got {without_opt_in_slot!r}"
    )
    assert silent_error.get("Code") == "ConditionalCheckFailed", (
        f"expected Error.Code 'ConditionalCheckFailed', got {silent_error.get('Code')!r}"
    )
    assert "Item" not in silent_error or silent_error.get("Item") is None, (
        f"without ReturnValuesOnConditionCheckFailure the Error must omit Item, got {silent_error.get('Item')!r}"
    )
    unchanged_silent = _stored(ddb, t, "silent")
    assert unchanged_silent == silent_item, (
        f"a rejected conditional UPDATE in the batch must not modify the item, got {unchanged_silent!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
