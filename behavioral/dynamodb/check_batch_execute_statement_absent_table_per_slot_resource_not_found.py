"""batch-execute-statement-absent-table-per-slot-resource-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-execute-statement-absent-table-per-slot-resource-not-found"
GROUP = "partiql"
SERVICES = ["dynamodb"]


def _partiql_table(ctx):
    ddb = ctx.client("dynamodb")
    t = ctx.unique_name("sim2real-behav-")
    ddb.create_table(
        TableName=t,
        KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return t


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """A BatchExecuteStatement member naming a table that does not exist fails only its own
    slot with Error.Code 'ResourceNotFound', and the sibling member on a real table still
    returns its Item; the same holds when every member names an absent table.

    Reference: https://docs.aws.amazon.com/amazondynamodb/latest/APIReference/API_BatchExecuteStatement.html
    """
    ddb = ctx.client("dynamodb")
    t = _partiql_table(ctx)
    ddb.put_item(TableName=t, Item={"pk": {"S": "p1"}, "sk": {"S": "s1"}, "v": {"S": "hit"}})
    absent = ctx.unique_name("sim2real-behav-absent-")

    resp = ddb.batch_execute_statement(Statements=[
        {"Statement": f"""SELECT * FROM "{absent}" WHERE pk='x' AND sk='y'"""},
        {"Statement": f"""SELECT * FROM "{t}" WHERE pk='p1' AND sk='s1'"""},
    ])
    responses = resp["Responses"]
    assert len(responses) == 2, f"expected 2 per-statement responses, got {len(responses)}: {responses!r}"

    bad = responses[0]
    assert "Item" not in bad, f"expected the absent-table slot to carry no Item, got {bad!r}"
    error = bad.get("Error")
    assert error is not None, (
        f"expected the absent-table statement to be a per-slot Error, not a thrown exception "
        f"aborting the whole batch, got {bad!r}"
    )
    assert error.get("Code") == "ResourceNotFound", f"expected Code ResourceNotFound, got {error.get('Code')!r}"
    assert error.get("Message") == "Requested resource not found", (
        f"expected AWS's exact message, got {error.get('Message')!r}"
    )

    # Positive control: the sibling statement, addressed at the real table in the SAME
    # batch call, is unaffected by its neighbour's rejection.
    good = responses[1]
    assert "Error" not in good, f"expected the real-table statement to succeed, got {good!r}"
    assert good.get("Item", {}).get("v") == {"S": "hit"}, (
        f"expected the real-table statement to return the seeded item, got {good!r}"
    )

    absent_2 = ctx.unique_name("sim2real-behav-absent2-")
    resp_all_absent = ddb.batch_execute_statement(Statements=[
        {"Statement": f"""SELECT * FROM "{absent}" WHERE pk='x' AND sk='y'"""},
        {"Statement": f"""SELECT * FROM "{absent_2}" WHERE pk='x' AND sk='y'"""},
    ])
    all_absent_responses = resp_all_absent["Responses"]
    assert len(all_absent_responses) == 2, (
        f"expected 2 per-statement responses even when every member names an absent table, "
        f"got {len(all_absent_responses)}: {all_absent_responses!r}"
    )
    for slot in all_absent_responses:
        slot_error = slot.get("Error")
        assert slot_error is not None, f"expected a per-slot Error, got {slot!r}"
        assert slot_error.get("Code") == "ResourceNotFound", (
            f"expected Code ResourceNotFound, got {slot_error.get('Code')!r}"
        )
        assert slot_error.get("Message") == "Requested resource not found", (
            f"expected AWS's exact message, got {slot_error.get('Message')!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
