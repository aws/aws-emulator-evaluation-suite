"""batch-execute-statement-index-qualified-select-rejected-per-slot."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-execute-statement-index-qualified-select-rejected-per-slot"
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
            {"AttributeName": "status", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[{
            "IndexName": "status-index",
            "KeySchema": [{"AttributeName": "status", "KeyType": "HASH"}],
            "Projection": {"ProjectionType": "ALL"},
        }],
        BillingMode="PAY_PER_REQUEST",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ddb.delete_table(TableName=t))
    ddb.get_waiter("table_exists").wait(TableName=t, WaiterConfig={"Delay": 2, "MaxAttempts": 250})
    return t


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchExecuteStatement reports a SELECT addressed at an index as a per-slot ValidationError,
    not a thrown exception aborting the batch, and a base-table sibling statement still succeeds.
    """
    ddb = ctx.client("dynamodb")
    t = _partiql_table(ctx)
    ddb.put_item(TableName=t, Item={"pk": {"S": "p1"}, "sk": {"S": "s1"}, "status": {"S": "active"}})

    resp = ddb.batch_execute_statement(Statements=[
        {"Statement": f"""SELECT * FROM "{t}"."status-index" WHERE status='active'"""},
        {"Statement": f"""SELECT * FROM "{t}" WHERE pk='p1' AND sk='s1'"""},
    ])
    responses = resp["Responses"]
    assert len(responses) == 2, f"expected 2 per-statement responses, got {len(responses)}: {responses}"

    bad = responses[0]
    assert "Item" not in bad, f"expected the index-qualified SELECT slot to carry no Item, got {bad}"
    error = bad.get("Error")
    assert error is not None, (
        f"expected the index-qualified SELECT to be reported as a per-slot Error "
        f"(not a thrown exception that would have aborted the whole batch), got {bad!r}"
    )
    assert error.get("Code") == "ValidationError", f"expected Code ValidationError, got {error.get('Code')!r}"
    assert error.get("Message") == (
        "Select statements within BatchExecuteStatement must specify the primary key in the where clause."
    ), f"unexpected message: {error.get('Message')!r}"

    # Positive control: the sibling statement, addressed at the base table in the SAME
    # batch call, is unaffected by its neighbour's rejection.
    good = responses[1]
    assert "Error" not in good, f"expected the base-table SELECT to succeed, got {good}"
    assert good.get("Item", {}).get("status") == {"S": "active"}, (
        f"expected the base-table SELECT to return the seeded item, got {good}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
