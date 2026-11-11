"""batch-execute-statement-non-key-and-index-key-select-rejected-no-table-name."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-execute-statement-non-key-and-index-key-select-rejected-no-table-name"
GROUP = "partiql"
SERVICES = ["dynamodb"]

_SELECT_ERROR = (
    "ValidationError",
    "Select statements within BatchExecuteStatement must specify the primary key in the where clause.",
)


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
    """A BatchExecuteStatement SELECT naming a non-key attribute on the base table, or naming
    both the table and index keys on an index-qualified member, fails its own slot with the same
    per-slot ValidationError and no TableName; a sibling keyed on the base table still returns.
    """
    ddb = ctx.client("dynamodb")
    t = _partiql_table(ctx)
    ddb.put_item(
        TableName=t,
        Item={"pk": {"S": "p1"}, "sk": {"S": "s1"}, "status": {"S": "active"}, "ss": {"S": "yes"}},
    )

    resp = ddb.batch_execute_statement(Statements=[
        {"Statement": f'''SELECT * FROM "{t}" WHERE attribute_exists(ss)'''},
        {"Statement": f'''SELECT * FROM "{t}"."status-index" WHERE pk='p1' AND status='active' '''},
        {"Statement": f'''SELECT * FROM "{t}" WHERE pk='p1' AND sk='s1' '''},
    ])
    responses = resp["Responses"]
    assert len(responses) == 3, f"expected 3 per-statement responses, got {len(responses)}: {responses!r}"

    non_key_slot, index_qualified_slot, good_slot = responses

    for label, slot in (("non-key base-table", non_key_slot), ("index-qualified", index_qualified_slot)):
        assert "Item" not in slot, f"expected the {label} SELECT slot to carry no Item, got {slot!r}"
        assert "TableName" not in slot, (
            f"expected the {label} SELECT's pre-run error slot to carry no TableName, got {slot!r}"
        )
        error = slot.get("Error")
        assert error is not None, (
            f"expected the {label} SELECT to be a per-slot Error, not a thrown exception aborting "
            f"the whole batch, got {slot!r}"
        )
        assert (error.get("Code"), error.get("Message")) == _SELECT_ERROR, (
            f"unexpected {label} slot error: {error!r}"
        )

    # Positive control: the sibling statement, keyed on the base table's primary key in the
    # SAME batch call, is unaffected by its neighbours' rejection and carries a TableName.
    assert "Error" not in good_slot, f"expected the base-table SELECT to succeed, got {good_slot!r}"
    assert good_slot.get("TableName") == t, f"expected the good slot's TableName to be {t!r}, got {good_slot!r}"
    assert good_slot.get("Item", {}).get("status") == {"S": "active"}, (
        f"expected the base-table SELECT to return the seeded item, got {good_slot!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
