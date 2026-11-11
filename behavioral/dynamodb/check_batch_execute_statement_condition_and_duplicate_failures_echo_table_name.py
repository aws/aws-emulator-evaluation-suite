"""batch-execute-statement-condition-and-duplicate-failures-echo-table-name."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-execute-statement-condition-and-duplicate-failures-echo-table-name"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _stored(ddb, table, pk):
    return ddb.get_item(TableName=table, Key={"pk": {"S": pk}}, ConsistentRead=True).get("Item")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A BatchExecuteStatement member that ran and failed echoes TableName: a conditional
    UPDATE failing its WHERE gives Error.Code 'ConditionalCheckFailed' and an INSERT of an
    existing key gives Error.Code 'DuplicateItem', both carrying the table's name.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_BatchExecuteStatement.html
    """
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})

    ddb.put_item(TableName=t, Item={"pk": {"S": "condfail"}, "val": {"S": "current"}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "dup1"}, "val": {"S": "original"}})
    ddb.put_item(TableName=t, Item={"pk": {"S": "ok"}, "val": {"S": "original-ok"}})

    resp = ddb.batch_execute_statement(Statements=[
        {
            "Statement": f'UPDATE "{t}" SET val = ? WHERE pk = ? AND val = ?',
            "Parameters": [{"S": "clobbered"}, {"S": "condfail"}, {"S": "WRONG-expected-value"}],
        },
        {"Statement": f"""INSERT INTO "{t}" VALUE {{'pk':'dup1','val':'second'}}"""},
        {
            "Statement": f'UPDATE "{t}" SET val = ? WHERE pk = ? AND val = ?',
            "Parameters": [{"S": "updated-ok"}, {"S": "ok"}, {"S": "original-ok"}],
        },
    ])
    responses = resp["Responses"]
    assert len(responses) == 3, f"expected 3 per-statement responses, got {len(responses)}: {responses!r}"
    cond_slot, dup_slot, ok_slot = responses

    cond_error = cond_slot.get("Error")
    assert cond_error is not None, f"expected a per-slot Error for the failed condition, got {cond_slot!r}"
    assert cond_error.get("Code") == "ConditionalCheckFailed", (
        f"expected Code ConditionalCheckFailed, got {cond_error.get('Code')!r}"
    )
    assert cond_error.get("Message") == "The conditional request failed", (
        f"expected AWS's exact message, got {cond_error.get('Message')!r}"
    )
    assert cond_slot.get("TableName") == t, (
        f"expected the failed slot to echo TableName {t!r}, got {cond_slot.get('TableName')!r}"
    )
    assert _stored(ddb, t, "condfail") == {"pk": {"S": "condfail"}, "val": {"S": "current"}}, (
        "a rejected conditional UPDATE in the batch must not modify the item"
    )

    dup_error = dup_slot.get("Error")
    assert dup_error is not None, f"expected a per-slot Error for the duplicate INSERT, got {dup_slot!r}"
    assert dup_error.get("Code") == "DuplicateItem", f"expected Code DuplicateItem, got {dup_error.get('Code')!r}"
    assert dup_error.get("Message") == "Duplicate primary key exists in table", (
        f"expected AWS's exact message, got {dup_error.get('Message')!r}"
    )
    assert dup_slot.get("TableName") == t, (
        f"expected the failed slot to echo TableName {t!r}, got {dup_slot.get('TableName')!r}"
    )
    assert _stored(ddb, t, "dup1") == {"pk": {"S": "dup1"}, "val": {"S": "original"}}, (
        "a rejected duplicate INSERT in the batch must not alter the existing item"
    )

    # Positive control: the well-formed sibling in the SAME batch call executed.
    assert "Error" not in ok_slot, f"expected the matching-condition UPDATE to succeed, got {ok_slot!r}"
    assert _stored(ddb, t, "ok") == {"pk": {"S": "ok"}, "val": {"S": "updated-ok"}}, (
        "the sibling's successful UPDATE must have applied"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
