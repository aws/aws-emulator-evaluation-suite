"""batch-execute-statement-or-sort-key-overlap-rejected-per-slot."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-execute-statement-or-sort-key-overlap-rejected-per-slot"
GROUP = "partiql"
SERVICES = ["dynamodb"]


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchExecuteStatement reports a WHERE clause ORing a non-key equality beside a sort-key
    branch as a per-slot ValidationError, not a thrown exception aborting the batch, and a
    sibling statement in the same call still succeeds.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-pqlbxor-")
    ddb.create_table(
        TableName=table,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=table))
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    ddb.put_item(TableName=table, Item={"pk": {"S": "p"}, "sk": {"S": "2"}, "hue": {"S": "red"}})

    resp = ddb.batch_execute_statement(Statements=[
        {"Statement": f"""SELECT * FROM "{table}" WHERE pk = 'p' AND hue = 'red' OR pk = 'p' AND sk = '2'"""},
        {"Statement": f"""SELECT * FROM "{table}" WHERE pk = 'p' AND sk = '2'"""},
    ])
    responses = resp["Responses"]
    assert len(responses) == 2, f"expected 2 per-statement responses, got {len(responses)}: {responses!r}"

    overlapping = responses[0]
    assert "Item" not in overlapping, (
        f"expected the overlapping-condition slot to carry no Item, got {overlapping!r}"
    )
    error = overlapping.get("Error")
    assert error is not None, (
        f"expected the overlapping-condition slot to be reported as a per-slot Error (not a "
        f"thrown exception that would have aborted the whole batch), got {overlapping!r}"
    )
    assert error.get("Code") == "ValidationError", f"expected Code ValidationError, got {error.get('Code')!r}"
    assert error.get("Message") == (
        "Overlapping conditions with range keys are not supported in where clause"
    ), f"unexpected message: {error.get('Message')!r}"

    # Positive control: the sibling statement, addressed at the same item with a plain key
    # equality, in the SAME batch call, is unaffected by its neighbour's rejection.
    sibling = responses[1]
    assert "Error" not in sibling, f"expected the sibling SELECT to succeed, got {sibling!r}"
    assert sibling.get("Item", {}).get("hue") == {"S": "red"}, (
        f"expected the sibling SELECT to return the seeded item, got {sibling!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
