"""batch-execute-statement-returning-delete-old-and-update-remove-modified-new."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "batch-execute-statement-returning-delete-old-and-update-remove-modified-new"
GROUP = "partiql"
SERVICES = ["dynamodb"]

_EXPECTED_INSERT_ERROR = ("ValidationError", "RETURNING is not supported in INSERT")


def _stored(ddb, table, pk, sk):
    return ddb.get_item(
        TableName=table, Key={"pk": {"S": pk}, "sk": {"S": sk}}, ConsistentRead=True,
    ).get("Item")


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """In one BatchExecuteStatement call, a DELETE member's RETURNING ALL OLD * carries the removed
    item, an UPDATE REMOVE member's RETURNING MODIFIED NEW * carries no Item but still echoes
    TableName, and an INSERT member with RETURNING is a per-slot Error, not a batch abort.
    """
    ddb = ctx.client("dynamodb")
    table = ctx.unique_name("sim2real-behav-pqlbrdr-")
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
    ddb.get_waiter("table_exists").wait(TableName=table, WaiterConfig={"Delay": 2, "MaxAttempts": 60})

    item_del = {"pk": {"S": "p1"}, "sk": {"S": "s1"}, "name": {"S": "Ada"}, "qty": {"N": "3"}}
    item_upd = {"pk": {"S": "p2"}, "sk": {"S": "s2"}, "qty": {"N": "5"}, "note": {"S": "n1"}}
    for item in (item_del, item_upd):
        ddb.put_item(TableName=table, Item=item)

    resp = ddb.batch_execute_statement(Statements=[
        {"Statement": f"DELETE FROM \"{table}\" WHERE pk = 'p1' AND sk = 's1' RETURNING ALL OLD *"},
        {"Statement": f"UPDATE \"{table}\" REMOVE note WHERE pk = 'p2' AND sk = 's2' RETURNING MODIFIED NEW *"},
        {"Statement": f"INSERT INTO \"{table}\" VALUE {{'pk':'p3','sk':'s3'}} RETURNING ALL OLD *"},
    ])
    responses = resp["Responses"]
    assert len(responses) == 3, f"expected 3 per-statement responses, got {len(responses)}: {responses}"
    slot_delete, slot_update, slot_insert = responses

    # Slot 1: DELETE ... RETURNING ALL OLD * carries the whole removed item and echoes TableName.
    assert "Error" not in slot_delete, f"expected the DELETE slot to succeed, got {slot_delete!r}"
    assert slot_delete.get("TableName") == table, (
        f"expected the DELETE slot to echo TableName={table!r}, got {slot_delete!r}"
    )
    assert slot_delete.get("Item") == item_del, (
        f"expected RETURNING ALL OLD * to carry the removed item {item_del!r}, "
        f"got {slot_delete.get('Item')!r}"
    )

    # Slot 2: UPDATE REMOVE ... RETURNING MODIFIED NEW * carries no Item, because the removed
    # attribute has no new value, but still echoes TableName since the statement succeeded.
    assert "Error" not in slot_update, f"expected the UPDATE slot to succeed, got {slot_update!r}"
    assert "Item" not in slot_update, (
        f"expected the REMOVE slot's MODIFIED NEW * to carry no Item, got {slot_update!r}"
    )
    assert slot_update.get("TableName") == table, (
        f"expected the successful UPDATE slot to echo TableName={table!r} even with no Item, "
        f"got {slot_update!r}"
    )

    # Slot 3: an INSERT member with a RETURNING clause is rejected as a per-slot Error, not a
    # thrown exception that aborts the other two members, and carries no Item or TableName.
    assert "Item" not in slot_insert, (
        f"expected the rejected INSERT slot to carry no Item, got {slot_insert!r}"
    )
    assert "TableName" not in slot_insert, (
        f"expected the rejected INSERT slot to carry no TableName (only a successful slot "
        f"echoes it), got {slot_insert!r}"
    )
    insert_error = slot_insert.get("Error")
    assert insert_error is not None, (
        f"expected the rejected INSERT slot to carry a per-slot Error, got {slot_insert!r}"
    )
    assert (insert_error.get("Code"), insert_error.get("Message")) == _EXPECTED_INSERT_ERROR, (
        f"expected {_EXPECTED_INSERT_ERROR!r}, got "
        f"{(insert_error.get('Code'), insert_error.get('Message'))!r}"
    )

    # The batch's mutations landed exactly where the per-slot outcomes say they did: p1 is gone,
    # p2 lost its removed attribute and kept the rest, and p3 was never inserted.
    assert _stored(ddb, table, "p1", "s1") is None, (
        f"p1 must have been deleted, got {_stored(ddb, table, 'p1', 's1')!r}"
    )
    want_upd = {k: v for k, v in item_upd.items() if k != "note"}
    assert _stored(ddb, table, "p2", "s2") == want_upd, (
        f"p2 must have had note removed, leaving {want_upd!r}, got {_stored(ddb, table, 'p2', 's2')!r}"
    )
    assert _stored(ddb, table, "p3", "s3") is None, (
        f"p3 must never have been inserted by the rejected statement, "
        f"got {_stored(ddb, table, 'p3', 's3')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
