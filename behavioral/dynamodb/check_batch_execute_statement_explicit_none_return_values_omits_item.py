"""batch-execute-statement-explicit-none-return-values-omits-item."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-execute-statement-explicit-none-return-values-omits-item"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _stored(ddb, table, pk):
    return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchExecuteStatement reports a per-statement conditional-write failure with
    ReturnValuesOnConditionCheckFailure explicitly set to NONE as a slot Error that carries no
    Item and leaves the item unchanged, while a sibling statement in the same batch applies.

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
    explicit_none_item = {"pk": {"S": "explicit-none"}, "val": {"S": "current-explicit-none"}}
    ddb.put_item(TableName=t, Item=ok_item)
    ddb.put_item(TableName=t, Item=explicit_none_item)

    resp = ddb.batch_execute_statement(Statements=[
        {
            "Statement": f'UPDATE "{t}" SET val = ? WHERE pk = ? AND val = ?',
            "Parameters": [{"S": "updated-ok"}, {"S": "ok"}, {"S": "original-ok"}],
        },
        {
            "Statement": f'UPDATE "{t}" SET val = ? WHERE pk = ? AND val = ?',
            "Parameters": [{"S": "clobbered"}, {"S": "explicit-none"}, {"S": "WRONG-expected-value"}],
            "ReturnValuesOnConditionCheckFailure": "NONE",
        },
    ])
    responses = resp["Responses"]
    assert len(responses) == 2, f"expected 2 per-statement responses, got {len(responses)}: {responses}"
    ok_slot, explicit_none_slot = responses

    assert "Error" not in ok_slot, f"expected the matching-condition UPDATE to succeed, got {ok_slot!r}"
    assert _stored(ddb, t, "ok") == {"pk": {"S": "ok"}, "val": {"S": "updated-ok"}}, (
        f"the sibling's successful UPDATE must have applied, got {_stored(ddb, t, 'ok')!r}"
    )

    error = explicit_none_slot.get("Error")
    assert error is not None, (
        f"expected the failing UPDATE slot to carry a per-slot Error, got {explicit_none_slot!r}"
    )
    assert error.get("Code") == "ConditionalCheckFailed", (
        f"expected Error.Code 'ConditionalCheckFailed', got {error.get('Code')!r}"
    )
    assert error.get("Message") == "The conditional request failed", (
        f"expected AWS's exact message, got {error.get('Message')!r}"
    )
    assert "Item" not in error, (
        f"ReturnValuesOnConditionCheckFailure=NONE must omit Item from the slot Error, got "
        f"{error.get('Item')!r}"
    )
    unchanged = _stored(ddb, t, "explicit-none")
    assert unchanged == explicit_none_item, (
        f"a rejected conditional UPDATE in the batch must not modify the item, got {unchanged!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
